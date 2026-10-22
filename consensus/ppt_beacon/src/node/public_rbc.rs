//! Reliable public AWSS transcript delivery and shared payload-fetch routing.
use async_recursion::async_recursion;
use types::{Replica, Round};
use types::beacon::{BeaconMsg, WrapperMsg};
use crate::node::{Context, CTRBCState};
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
            PptWire::TransformedShares{..}=>{}, // v4 reconstruction is not accepted in v5
            PptWire::AuditDisclosure{..}=>{}, // v4 all-dealer disclosures are not imported
            PptWire::AuditCertificate{..}=>{}, // Legacy slot: only direct provider rows enter audits.
            PptWire::AuditRecovered{..}=>{},
            message @ PptWire::ReserveTransport{..}|message @ PptWire::ReserveRequest{..}|message @ PptWire::ReserveRecovered{..}=>self.process_reserve_wire(message,sender).await,
            PptWire::Compact{scope,round,proposer,message}=>self.process_compact_broadcast(scope,round,proposer,message,sender).await,
            PptWire::BatchRec{round,context,stage,values}=>self.process_batch_rec(round,context,stage,values,sender).await,
            PptWire::DealerAudit{round,dealer,entry}=>self.process_dealer_audit(round,dealer,entry,sender).await,
            PptWire::DealerAuditRequest{round,dealer,root}=>self.process_dealer_audit_request(round,dealer,root,sender).await,
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

    pub(crate) async fn start_public_rbc(&mut self,bundle:PublicBundle) {
        let round=bundle.public.round;let proposer=bundle.public.origin;
        self.start_compact_broadcast(RbcScope::PublicCommit,round,proposer,
            bincode::serialize(&bundle).expect("public AWSS encoding")).await;
    }

    // Old full-payload RBC wire slots remain decodable, but never enter v5 instances.
    pub(crate) async fn process_scoped_rbc(&mut self,_scope:RbcScope,_round:Round,
        _proposer:Replica,_message:RbcMessage,_sender:Replica) {}

    #[async_recursion]
    pub(crate) async fn accept_public_bundle(&mut self, bundle: PublicBundle) {
        let public = &bundle.public;
        let round = public.round; let dealer = public.origin;
        let total = self.batch_size + super::context::PPT_COIN_RESERVE;
        if bundle.version != wire::PUBLIC_BUNDLE_VERSION || !public.verify_transcript_root() || public.root_vec.len() != total
            || !super::batch_degree_test::public_shape(public, self.batch_size, self.num_nodes,
                self.num_faults, self.gf2_profile) {
            log::warn!("[PPT][PUBLIC-RBC] rejected malformed public transcript round={} dealer={}", round, dealer);
            return;
        }
        if self.round_state.get(&round).map(|state| state.cleared).unwrap_or(false) { return; }
        if self.transport == super::context::AvssTransport::SecMsg && (bundle.secmsg_roots.is_none()||bundle.reserve_roots.is_none()) {
            log::warn!("[PPT][PUBLIC-RBC] SecMsg transcript lacks key/cipher commitments"); return;
        }
        let expected_challenge=if self.transport==super::context::AvssTransport::SecMsg {
            self.gf2_profile.map(|profile|super::batch_degree_test::secmsg_input_root(round,dealer,
                &public.root_vec,bundle.secmsg_roots.expect("checked SecMsg commitments"),
                self.batch_size,self.num_nodes,self.num_faults,profile))
        }else{None};
        if bundle.challenge_root!=expected_challenge {
            log::warn!("[PPT][PUBLIC-RBC] main challenge input is not bound to the encrypted batch");return;
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
