use std::time::SystemTime;

use async_recursion::async_recursion;
use crypto::hash::Hash;
use types::beacon::{CTRBCMsg, Replica, CoinMsg};

use crate::node::{Context, CTRBCState};

/**
 * Check out Cachin-Tessaro's RBC protocol for details on READY processing and READY messages
 */
impl Context{
    #[async_recursion]
    pub async fn process_ready(self: &mut Context, ctrbc:CTRBCMsg,master_root:Hash,ready_sender:Replica){
        let _now = SystemTime::now();
        if !self.round_state.contains_key(&ctrbc.round){
            let rbc_new_state = CTRBCState::new(self.secret_domain.clone(),self.num_nodes);
            self.round_state.insert(ctrbc.round, rbc_new_state);
        }
        let rbc_state = self.round_state.get_mut(&ctrbc.round).unwrap();
        let sec_origin = ctrbc.origin;

        // Phase 3: Skip readys for dealers already flagged as malicious
        if rbc_state.malicious_dealers.contains(&sec_origin) {
            log::warn!("[BLAME] Ignoring READY for malicious dealer {} in round {}", sec_origin, ctrbc.round);
            return;
        }

        log::info!("Received READY message from {} for secret from {} in round {}",ready_sender,ctrbc.origin,ctrbc.round);
        if rbc_state.terminated_secrets.contains(&sec_origin){
            log::info!("Terminated secretsharing of instance {} already, skipping this echo",sec_origin);
            return;
        }
        match rbc_state.msgs.get(&sec_origin){
            None => {
                rbc_state.add_ready(sec_origin, ready_sender, &ctrbc);
                return;
            }
            Some(_x) =>{}
        }
        let (_beacon,shard) = rbc_state.msgs.get(&sec_origin).unwrap();
        let mp = shard.mp.clone();
        if mp.root() != master_root || !ctrbc.verify_mr_proof(&self.hash_context){
            log::error!("Merkle root of WSS Init from {} did not match Merkle root of READY from {}",sec_origin,self.myid);
            return;
        }
        rbc_state.add_ready(sec_origin, ready_sender, &ctrbc);
        let res = rbc_state.ready_check(sec_origin, self.num_nodes.clone(), self.num_faults.clone(), self.batch_size.clone(),&self.hash_context);
        match res.1{
            None => {
                return;
            }
            Some(root_vec) =>{
                // Conduct Bracha Amplification
                if res.0 == self.num_faults +1{
                    let shard = rbc_state.echos.get(&sec_origin).unwrap().get(&self.myid).unwrap();
                    let ctrbc = CTRBCMsg::new(shard.0.clone(), shard.1.clone(), ctrbc.round, sec_origin);
                    rbc_state.add_ready(sec_origin, self.myid, &ctrbc);
                    self.broadcast(CoinMsg::CTRBCReady(ctrbc.clone(),root_vec.0, self.myid),ctrbc.round).await;
                }
                else if res.0 == self.num_nodes-self.num_faults {
                    let shard = rbc_state.echos.get(&sec_origin).unwrap().get(&self.myid).unwrap();
                    let ctrbc = CTRBCMsg::new(shard.0.clone(), shard.1.clone(), ctrbc.round, sec_origin);
                    self.broadcast(CoinMsg::CTRBCReconstruct(ctrbc.clone(),master_root.clone(), self.myid),ctrbc.round).await;
                    self.process_reconstruct(ctrbc,master_root.clone(),self.myid).await;
                }
                else {
                    return;
                }
            }
        }
    }
}
