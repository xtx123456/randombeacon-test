//! Live driver for JoC Fig. 5. Reliable authenticated links deliver each
//! honest ECHO to every peer; no whole-payload retrieval fan-in is needed.
use async_recursion::async_recursion;
use types::{Replica,Round};
use super::{Context,wire::{self,PptWire,RbcScope,CompactMessage}};
use super::shoup_smart::compact_broadcast::{CompactBroadcastState,CompactBroadcastAction};

impl Context {
    fn compact_limit(&self,scope:RbcScope)->usize {
        match scope {
            RbcScope::PublicCommit=>super::payload_limits::public_bundle(self.batch_size,self.num_nodes,self.gf2_profile.is_some()).unwrap_or(0),
            RbcScope::AcsProposal=>self.num_nodes.checked_mul(std::mem::size_of::<Replica>()).and_then(|v|v.checked_add(4)).unwrap_or(0),
        }
    }

    fn compact_state(&mut self,scope:RbcScope,round:Round,proposer:Replica)->&mut CompactBroadcastState {
        let myid=self.myid;let n=self.num_nodes;let f=self.num_faults;
        let hash=self.hash_context.clone();let limit=self.compact_limit(scope);
        let map=match scope {RbcScope::PublicCommit=>&mut self.avss_public_rbc,RbcScope::AcsProposal=>&mut self.acs_compact_rbc};
        map.entry((round,proposer)).or_insert_with(||{
            let mut state=CompactBroadcastState::new(myid,n,f,proposer,hash).expect("validated broadcast configuration");
            state.set_message_limit(limit);state
        })
    }

    #[async_recursion]
    pub(crate) async fn start_compact_broadcast(&mut self,scope:RbcScope,round:Round,proposer:Replica,payload:Vec<u8>) {
        if proposer!=self.myid || payload.len()>self.compact_limit(scope) {return;}
        let actions=match self.compact_state(scope,round,proposer).set_input_as_proposer(payload) {
            Ok(actions)=>actions,Err(error)=>{log::error!("[PPT][COMPACT] input failed: {}",error);return;}
        };
        self.dispatch_compact(scope,round,proposer,actions).await;
    }

    #[async_recursion]
    pub(crate) async fn process_compact_broadcast(&mut self,scope:RbcScope,round:Round,proposer:Replica,message:CompactMessage,sender:Replica) {
        if sender>=self.num_nodes || proposer>=self.num_nodes || round>self.max_rounds {return;}
        // Completed instances retain a tombstone. Never recreate a retired instance.
        if self.round_state.get(&round).map(|s|s.cleared).unwrap_or(false)
            && match scope {RbcScope::PublicCommit=>!self.avss_public_rbc.contains_key(&(round,proposer)),RbcScope::AcsProposal=>!self.acs_compact_rbc.contains_key(&(round,proposer))} {return;}
        let state=self.compact_state(scope,round,proposer);
        let actions=match message {
            CompactMessage::Dispersal{root,path,fragment}=>state.handle_dispersal(sender,root,path,fragment),
            CompactMessage::Echo{root,path,fragment,index}=>state.handle_echo(sender,root,path,fragment,index),
            CompactMessage::Vote(root)=>state.handle_vote(sender,root),
        };
        self.dispatch_compact(scope,round,proposer,actions).await;
    }

    #[async_recursion]
    async fn dispatch_compact(&mut self,scope:RbcScope,round:Round,proposer:Replica,actions:Vec<CompactBroadcastAction>) {
        for action in actions {
            let message=match action {
                CompactBroadcastAction::SendDispersal{recipient_idx,root,path,fragment}=>{
                    self.send_ppt_wire(recipient_idx,round,PptWire::Compact{scope,round,proposer,
                        message:CompactMessage::Dispersal{root,path,fragment}}).await;continue;
                }
                CompactBroadcastAction::SendEcho{root,path,fragment,frag_idx}=>CompactMessage::Echo{root,path,fragment,index:frag_idx},
                CompactBroadcastAction::SendVote{root}=>CompactMessage::Vote(root),
                CompactBroadcastAction::Delivered{message}=>{
                    match scope {
                        RbcScope::PublicCommit=>if let Ok(bundle)=bincode::deserialize::<super::wire::PublicBundle>(&message) {
                            if bundle.public.origin==proposer && bundle.public.round==round {self.accept_public_bundle(bundle).await;}
                        },
                        RbcScope::AcsProposal=>self.on_rbc_delivered(round,proposer,message).await,
                    }
                    continue;
                }
                CompactBroadcastAction::Rejected{root}=>{
                    log::warn!("[PPT][COMPACT] rejected non-codeword round={} proposer={} root={:?}",round,proposer,root);
                    if scope==RbcScope::AcsProposal {self.acs_reject_proposal(round,proposer).await;}
                    continue;
                }
            };
            self.broadcast(wire::encode(&PptWire::Compact{scope,round,proposer,message:message.clone()}),round).await;
            // The state machine counts its own ECHO/VOTE; repeating is idempotent.
            self.process_compact_broadcast(scope,round,proposer,message,self.myid).await;
        }
        if scope==RbcScope::AcsProposal {self.acs_external_scan_finalize_only(round).await;}
    }
}
