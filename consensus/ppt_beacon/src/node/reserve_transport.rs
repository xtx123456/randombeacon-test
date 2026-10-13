//! Independently encrypted PR10 coin reserves. Beacon audit keys cannot open
//! these ciphertexts. The common-coin derivation/reveal algorithm is unchanged.
use std::collections::HashSet;
use async_recursion::async_recursion;
use num_bigint::BigUint;
use types::{Replica,Round};
use types::beacon::AvssRecipientPayload;
use super::{Context,wire::{self,PptWire,RmdPacket},shoup_smart::sec_msg_dst::{SecMsgDstState,SecMsgDstAction,SecMsgChannel}};

#[derive(Default)]
pub(crate) struct ReserveServing { requested:bool, requests:HashSet<Replica>, replayed:HashSet<(Replica,SecMsgChannel)>, ack_sent:bool, acks:HashSet<Replica> }
pub(crate) fn key_prime()->BigUint {(BigUint::from(1u8)<<521usize)-BigUint::from(1u8)}

impl Context {
    pub(crate) fn get_or_init_reserve(&mut self,round:Round,dealer:Replica)->&mut SecMsgDstState {
        if !self.reserve_state.contains_key(&(round,dealer)) {
            let mut state=SecMsgDstState::new(self.myid,self.num_nodes,self.num_faults,dealer,key_prime(),self.hash_context.clone()).expect("validated SecMsg configuration");
            if let Some((key,cipher))=self.avss_public_bundles.get(&(round,dealer)).and_then(|b|b.reserve_roots){state.bind_roots(key,cipher);}
            self.reserve_state.insert((round,dealer),state);
        }self.reserve_state.get_mut(&(round,dealer)).unwrap()
    }
    #[async_recursion]
    pub(crate) async fn process_reserve_wire(&mut self,message:PptWire,sender:Replica) {
        let (round,dealer)=match &message {PptWire::ReserveTransport{round,dealer,..}|PptWire::ReserveRequest{round,dealer,..}|PptWire::ReserveRecovered{round,dealer,..}=>(*round,*dealer),_=>return};
        if sender>=self.num_nodes||dealer>=self.num_nodes||round>self.max_rounds{return;}
        if self.avss_public_bundles.get(&(round,dealer)).and_then(|b|b.reserve_roots).is_none() {
            if self.round_state.get(&round).map(|s|s.cleared).unwrap_or(false){return;}
            let pending=self.reserve_pending.entry((round,dealer)).or_default();
            // One canonical slot per sender/channel/packet kind.
            let slot=reserve_slot(&message);
            if !pending.iter().any(|(m,p)|*p==sender&&reserve_slot(m)==slot){pending.push((message,sender));}return;
        }
        match message {
            PptWire::ReserveTransport{channel,packet,..}=>{
                self.get_or_init_reserve(round,dealer);
                let mut state=self.reserve_state.remove(&(round,dealer)).unwrap();
                let result=tokio::task::spawn_blocking(move||{
                    let actions=match (channel,packet){
                        (SecMsgChannel::Key,RmdPacket::Dispersal(v))=>state.handle_key_dispersal(sender,v),
                        (SecMsgChannel::Cipher,RmdPacket::Dispersal(v))=>state.handle_cipher_dispersal(sender,v),
                        (SecMsgChannel::Key,RmdPacket::Echo(v))=>state.handle_key_echo(sender,v),
                        (SecMsgChannel::Cipher,RmdPacket::Echo(v))=>state.handle_cipher_echo(sender,v),
                        (SecMsgChannel::Key,RmdPacket::Vote(v))=>state.handle_key_vote(sender,v),
                        (SecMsgChannel::Cipher,RmdPacket::Vote(v))=>state.handle_cipher_vote(sender,v),
                    };(state,actions)
                }).await;
                if let Ok((state,actions))=result{self.reserve_state.insert((round,dealer),state);self.dispatch_reserve_actions(round,dealer,actions).await;}
                else{log::error!("[PPT][RESERVE] transport worker failed round={} dealer={}",round,dealer);}
            }
            PptWire::ReserveRequest{recipient,..}=>{if recipient!=sender{return;}
                if !self.awss_selected(round,dealer){
                    let pending=self.reserve_pending.entry((round,dealer)).or_default();
                    if !pending.iter().any(|(m,p)|*p==sender&&matches!(m,PptWire::ReserveRequest{..})){
                        pending.push((PptWire::ReserveRequest{round,dealer,recipient},sender));
                    }return;
                }
                self.reserve_serving.entry((round,dealer)).or_default().requests.insert(recipient);self.drive_reserve_replay(round,dealer).await;}
            PptWire::ReserveRecovered{..}=>{self.reserve_serving.entry((round,dealer)).or_default().acks.insert(sender);self.release_reserve_if_safe(round,dealer);}
            _=>{}
        }
    }
    #[async_recursion]
    pub(crate) async fn dispatch_reserve_actions(&mut self,round:Round,dealer:Replica,actions:Vec<SecMsgDstAction>) {
        for action in actions {match action {
            SecMsgDstAction::SendDispersal{channel,recipient_idx,entries}=>self.send_ppt_wire(recipient_idx,round,PptWire::ReserveTransport{round,dealer,channel,packet:RmdPacket::Dispersal(entries)}).await,
            SecMsgDstAction::SendEcho{channel,recipient_idx,echo}=>self.send_ppt_wire(recipient_idx,round,PptWire::ReserveTransport{round,dealer,channel,packet:RmdPacket::Echo(echo)}).await,
            SecMsgDstAction::SendVote{channel,meta_root}=>{
                let message=PptWire::ReserveTransport{round,dealer,channel,packet:RmdPacket::Vote(meta_root)};
                self.broadcast(wire::encode(&message),round).await;self.process_reserve_wire(message,self.myid).await;
            }
            SecMsgDstAction::DeliveredMessage{message}=>{
                self.reserve_bytes.entry((round,dealer)).or_insert(message);
                self.install_reserved_material(round,dealer).await;
                self.join_secmsg_parts(round,dealer).await;
                let state=self.reserve_serving.entry((round,dealer)).or_default();
                if !state.ack_sent{state.ack_sent=true;state.acks.insert(self.myid);
                    self.broadcast(wire::encode(&PptWire::ReserveRecovered{round,dealer}),round).await;}
            }
            _=>{} // Reserve disclosures/complaint assists are never part of batch audit.
        }}self.drive_reserve_replay(round,dealer).await;
    }
    #[async_recursion]
    pub(crate) async fn drive_reserve_replay(&mut self,round:Round,dealer:Replica) {
        let requests:Vec<_>=self.reserve_serving.entry((round,dealer)).or_default().requests.iter().copied().collect();
        for recipient in requests {
            let actions=self.reserve_state.get(&(round,dealer)).map(|s|s.replay_for_recipient(recipient)).unwrap_or_default();
            let mut fresh=Vec::new();for action in actions {if let SecMsgDstAction::SendEcho{channel,..}=&action {
                if self.reserve_serving.get_mut(&(round,dealer)).unwrap().replayed.insert((recipient,*channel)){fresh.push(action);}
            }}if !fresh.is_empty(){self.dispatch_reserve_actions(round,dealer,fresh).await;}
        }
    }
    #[async_recursion]
    pub(crate) async fn request_selected_reserve(&mut self,round:Round,dealer:Replica) {
        let pending=self.reserve_pending.remove(&(round,dealer)).unwrap_or_default();
        for (message,sender) in pending{self.process_reserve_wire(message,sender).await;}
        if self.transport!=super::AvssTransport::SecMsg||self.reserve_bytes.contains_key(&(round,dealer)){return;}
        let state=self.reserve_serving.entry((round,dealer)).or_default();if state.requested{return;}state.requested=true;
        self.broadcast(wire::encode(&PptWire::ReserveRequest{round,dealer,recipient:self.myid}),round).await;
    }
    #[async_recursion]
    pub(crate) async fn install_reserved_material(&mut self,round:Round,dealer:Replica) {
        let material=match self.coin_material.get(&round){Some(m) if m.decided.contains(&dealer)&&!m.my_shares.contains_key(&dealer)=>m,_=>return};
        let _=material;
        let payload=match self.reserve_bytes.get(&(round,dealer)).and_then(|b|AvssRecipientPayload::deserialize_bytes(b)){Some(p)=>p,None=>return};
        let public=match self.avss_secmsg_public.get(&(round,dealer)){Some(p)=>p,None=>return};
        let count=super::context::PPT_COIN_RESERVE;
        if !super::share_pipeline::validate_original(public,&payload,self.batch_size,count,self.myid,self.num_nodes,self.num_faults,
            &self.secret_domain,&self.nonce_domain,self.gf2_profile,&self.hash_context){return;}
        let shares=(0..count).map(|i|(payload.secrets[i],payload.mask_shares[i],
            payload.f_large_shares.as_ref().map(|v|v[i]).unwrap_or(payload.secrets[i]),payload.nonces[i],payload.mps[i].clone())).collect();
        self.coin_material.get_mut(&round).unwrap().my_shares.insert(dealer,shares);
        // Retry availability of the SAME sealed coin, never introduce a new
        // coin value or alter PR10's derivation/reveal timing.
        let next=round+1;self.coin_reveal_sent.retain(|(r,_)|*r!=next);
        self.acs_note_local_change(next).await;
    }
    #[async_recursion]
    pub(crate) async fn join_secmsg_parts(&mut self,round:Round,dealer:Replica) {
        if self.avss_secmsg_delivered_bytes.contains_key(&(round,dealer)){return;}
        let beacon=match self.avss_beacon_bytes.get(&(round,dealer)).and_then(|b|AvssRecipientPayload::deserialize_bytes(b)){Some(p)=>p,None=>return};
        let reserve=match self.reserve_bytes.get(&(round,dealer)).and_then(|b|AvssRecipientPayload::deserialize_bytes(b)){Some(p)=>p,None=>return};
        if beacon.secrets.len()!=self.batch_size||reserve.secrets.len()!=super::context::PPT_COIN_RESERVE{return;}
        if let Some(payload)=super::share_pipeline::join_payloads(beacon,reserve){
            self.avss_secmsg_delivered_bytes.insert((round,dealer),payload.serialize_bytes());
            self.try_finalize_avss_secmsg(round,dealer).await;
        }
    }
    pub(crate) fn release_reserve_if_safe(&mut self,round:Round,dealer:Replica) {
        let next_done=self.acs_state.get(&(round+1)).map(|s|s.finalized).unwrap_or(false);
        let all=self.reserve_serving.get(&(round,dealer)).map(|s|s.acks.len()==self.num_nodes).unwrap_or(false);
        if next_done&&all {
            self.reserve_state.remove(&(round,dealer));self.reserve_bytes.remove(&(round,dealer));self.reserve_pending.remove(&(round,dealer));
            if !self.avss_secmsg_state.contains_key(&(round,dealer))&&self.round_state.get(&round).map(|s|s.cleared).unwrap_or(false){
                self.avss_secmsg_public.remove(&(round,dealer));self.avss_public_bundles.remove(&(round,dealer));self.avss_public_rbc.remove(&(round,dealer));
            }
        }
    }
}
fn reserve_slot(message:&PptWire)->(u8,u8) {match message{
    PptWire::ReserveTransport{channel,packet,..}=>(*channel as u8,match packet{RmdPacket::Dispersal(_)=>0,RmdPacket::Echo(_)=>1,RmdPacket::Vote(_)=>2}),
    PptWire::ReserveRequest{..}=>(2,0),_ =>(3,0),
}}
