//! Reliable public AWSS transcript delivery and shared payload-fetch routing.
use async_recursion::async_recursion;
use types::{Replica, Round};
use types::beacon::{BeaconMsg, WrapperMsg};
use crate::node::{Context, CTRBCState};
use super::acs::rbc::{RbcAction, RbcInstanceState};
use super::wire::{self, PptWire, PublicBundle, RbcScope, RbcMessage};

pub(crate) fn transcript(public: &types::beacon::AvssPublicCommitMsg) -> BeaconMsg {
    BeaconMsg { origin: public.origin, round: public.round, wss: None,
        root_vec: Some(public.root_vec.clone()), appx_con: Some(Vec::new()),
        degree_test_coeffs: Some(public.degree_test_coeffs.clone()),
        mask_shares: None, f_large_shares: None }
}

impl Context {
    #[async_recursion]
    pub(crate) async fn send_ppt_wire(&mut self, recipient: Replica, round: Round, message: PptWire) {
        if recipient == self.myid {
            self.process_ppt_wire(message, self.myid).await;
        } else if let Some(key) = self.sec_key_map.get(&recipient) {
            let wrapper = WrapperMsg::new(wire::encode(&message), self.myid, key, round);
            self.send(recipient, wrapper).await;
        }
    }

    #[async_recursion]
    pub(crate) async fn process_ppt_wire(&mut self, message: PptWire, sender: Replica) {
        match message {
            PptWire::TransformedShares{round,dealers,values}=>self.process_transformed_shares(round,dealers,values,sender).await,
            PptWire::AuditDisclosure{round,dealers,entries}=>self.process_full_audit_disclosure(round,dealers,entries,sender).await,
            PptWire::AuditCertificate{round,dealers,rows}=>self.process_audit_certificate(round,dealers,rows,sender).await,
            PptWire::AuditRecovered{round}=>self.note_audit_ack(round,sender),
            message @ PptWire::ReserveTransport{..}|message @ PptWire::ReserveRequest{..}|message @ PptWire::ReserveRecovered{..}=>self.process_reserve_wire(message,sender).await,
            PptWire::Rbc { scope, round, proposer, message } => {
                self.process_scoped_rbc(scope, round, proposer, message, sender).await;
            }
            message @ PptWire::AwssRequest { .. }
            | message @ PptWire::AwssRecovered { .. }
            | message @ PptWire::AwssForward { .. }
            | message @ PptWire::AwssChannelForward { .. } => self.process_awss_wire(message, sender).await,
            PptWire::Private { .. } => {
                // Network private envelopes are consumed before the dispatcher.
                log::warn!("[PPT][WIRE] unexpected private envelope after authentication");
            }
        }
    }

    #[async_recursion]
    pub(crate) async fn start_public_rbc(&mut self, bundle: PublicBundle) {
        let round = bundle.public.round;
        let proposer = bundle.public.origin;
        let payload = bincode::serialize(&bundle).expect("public AWSS bundle encoding");
        let myid = self.myid; let n = self.num_nodes; let f = self.num_faults;
        let actions = self.avss_public_rbc.entry((round, proposer)).or_insert_with(||
            RbcInstanceState::new(myid, proposer, n, f))
            .proposer_send(payload);
        self.dispatch_public_rbc(round, proposer, actions).await;
    }

    #[async_recursion]
    pub(crate) async fn process_scoped_rbc(&mut self, scope: RbcScope, round: Round,
        proposer: Replica, message: RbcMessage, sender: Replica) {
        if sender >= self.num_nodes || proposer >= self.num_nodes { return; }
        if matches!(&message, RbcMessage::Send(_)) && sender != proposer { return; }
        if scope == RbcScope::AcsProposal {
            self.process_acs_rbc_retrieval(round, proposer, sender, message).await;
            return;
        }
        if self.round_state.get(&round).map(|state| state.cleared).unwrap_or(false)
            && !self.avss_public_rbc.contains_key(&(round, proposer)) { return; }
        // Requests can still be served after local batch cleanup. A slow honest
        // recipient must not depend on the Byzantine proposer sending again.
        let myid = self.myid; let n = self.num_nodes; let f = self.num_faults;
        let state = self.avss_public_rbc.entry((round, proposer))
            .or_insert_with(|| RbcInstanceState::new(myid, proposer, n, f));
        let actions = match message {
            RbcMessage::Send(payload) => {
                let bundle: PublicBundle = match bincode::deserialize(&payload) { Ok(value) => value, Err(_) => return };
                if bundle.public.origin != proposer || bundle.public.round != round
                    || !bundle.public.verify_transcript_root() { return; }
                state.handle_send(sender, payload)
            }
            RbcMessage::Echo(hash) => state.handle_echo(sender, hash),
            RbcMessage::Ready(hash) => state.handle_ready(sender, hash),
            RbcMessage::Request(hash) => state.handle_request(sender, hash),
            RbcMessage::Payload(hash, payload) => state.handle_payload(sender, hash, payload),
        };
        self.dispatch_public_rbc(round, proposer, actions).await;
    }

    #[async_recursion]
    async fn dispatch_public_rbc(&mut self, round: Round, proposer: Replica, actions: Vec<RbcAction>) {
        for action in actions {
            let message = match action {
                RbcAction::SendSend { payload } => RbcMessage::Send(payload),
                RbcAction::SendEcho { payload_hash } => RbcMessage::Echo(payload_hash),
                RbcAction::SendReady { payload_hash } => RbcMessage::Ready(payload_hash),
                RbcAction::RequestPayload { payload_hash } => RbcMessage::Request(payload_hash),
                RbcAction::SendPayload { recipient, payload_hash, payload } => {
                    self.send_ppt_wire(recipient, round, PptWire::Rbc {
                        scope: RbcScope::PublicCommit, round, proposer,
                        message: RbcMessage::Payload(payload_hash, payload) }).await;
                    continue;
                }
                RbcAction::Delivered { payload } => {
                    if let Ok(bundle) = bincode::deserialize::<PublicBundle>(&payload) {
                        if bundle.public.origin == proposer && bundle.public.round == round {
                            self.accept_public_bundle(bundle).await;
                        }
                    }
                    continue;
                }
            };
            let wire = PptWire::Rbc { scope: RbcScope::PublicCommit, round, proposer, message: message.clone() };
            self.broadcast(wire::encode(&wire), round).await;
            self.process_scoped_rbc(RbcScope::PublicCommit, round, proposer, message, self.myid).await;
        }
    }

    #[async_recursion]
    pub(crate) async fn accept_public_bundle(&mut self, bundle: PublicBundle) {
        let public = &bundle.public;
        let round = public.round; let dealer = public.origin;
        let total = self.batch_size + super::context::PPT_COIN_RESERVE;
        if bundle.version != 2 || !public.verify_transcript_root() || public.root_vec.len() != total
            || !super::batch_degree_test::public_shape(public, self.batch_size, self.num_nodes,
                self.num_faults, self.gf2_profile) {
            log::warn!("[PPT][PUBLIC-RBC] rejected malformed public transcript round={} dealer={}", round, dealer);
            return;
        }
        if self.round_state.get(&round).map(|state| state.cleared).unwrap_or(false) { return; }
        if self.transport == super::context::AvssTransport::SecMsg && (bundle.secmsg_roots.is_none()||bundle.reserve_roots.is_none()) {
            log::warn!("[PPT][PUBLIC-RBC] SecMsg transcript lacks key/cipher commitments"); return;
        }
        let roots = bundle.secmsg_roots;
        let reserve_roots=bundle.reserve_roots;
        let header = transcript(public);
        let root = crypto::hash::do_hash(&header.serialize_ctrbc());
        let domain = self.secret_domain.clone(); let n = self.num_nodes;
        let state = self.round_state.entry(round).or_insert_with(|| CTRBCState::new(domain, n));
        state.comm_vectors.insert(dealer, public.root_vec.clone());
        state.degree_test_coeffs.insert(dealer, public.degree_test_coeffs.clone());
        state.avss_transcript_roots.insert(dealer, root);
        self.avss_secmsg_public.insert((round, dealer), public.clone());
        self.avss_public_bundles.insert((round, dealer), bundle);
        if let Some((key, cipher)) = roots {
            if !self.get_or_init_avss_secmsg(round, dealer).bind_roots(key, cipher) { return; }
            let pending = self.avss_secmsg_pending.remove(&(round, dealer)).unwrap_or_default();
            for (message, sender) in pending { self.dispatch_self_avss_secmsg(message, sender).await; }
        }
        if let Some((key,cipher))=reserve_roots {
            if !self.get_or_init_reserve(round,dealer).bind_roots(key,cipher){return;}
            let pending=self.reserve_pending.remove(&(round,dealer)).unwrap_or_default();
            for (message,sender) in pending{self.process_reserve_wire(message,sender).await;}
        }
        self.try_finalize_avss_secmsg(round, dealer).await;
        self.refresh_awss_prepared(round, dealer).await;
        self.drive_awss_recovery(round, dealer).await;
        self.maybe_recover_ready_coins(round).await;
    }
}
