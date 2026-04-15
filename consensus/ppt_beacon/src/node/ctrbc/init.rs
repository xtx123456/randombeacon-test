use std::time::SystemTime;

use types::{beacon::{BeaconMsg, CoinMsg}, beacon::CTRBCMsg};

use crate::node::{Context, CTRBCState};
use crate::node::ctrbc::state::BlameReason;

impl Context{
    pub async fn process_rbcinit(self: &mut Context, beacon_msg:BeaconMsg,ctr:CTRBCMsg){
        let now = SystemTime::now();
        let round = beacon_msg.round;
        let dealer = ctr.origin;

        // Phase 3: Ensure round state exists before blame recording
        if !self.round_state.contains_key(&round){
            let rbc_new_state = CTRBCState::new(self.secret_domain.clone(),self.num_nodes);
            self.round_state.insert(round, rbc_new_state);
        }

        // Phase 3: Check if dealer is already blamed — skip immediately
        {
            let rbc_state = self.round_state.get(&round).unwrap();
            if rbc_state.malicious_dealers.contains(&dealer) {
                log::warn!("[BLAME] Dealer {} already flagged as malicious, ignoring RBC Init in round {}", dealer, round);
                return;
            }
        }

        // Validate RBC shard Merkle proof
        if !ctr.verify_mr_proof(&self.hash_context){
            log::error!("[BLAME] Invalid RBC shard Merkle Proof from dealer {} in round {}", dealer, round);
            let rbc_state = self.round_state.get_mut(&round).unwrap();
            rbc_state.blame_dealer(dealer, round, BlameReason::InvalidRBCShardProof);
            return;
        }

        // Validate WSS batch Merkle proofs
        if !beacon_msg.verify_proofs(&self.hash_context){
            log::error!("[BLAME] Invalid WSS batch Merkle Proof from dealer {} in round {}", dealer, round);
            let rbc_state = self.round_state.get_mut(&round).unwrap();
            rbc_state.blame_dealer(dealer, round, BlameReason::InvalidWSSBatchProof);
            return;
        }

        log::info!("Received RBC Init from node {} for round {}",dealer,round);
        let rbc_state = self.round_state.get_mut(&round).unwrap();
        rbc_state.add_message(beacon_msg.clone(),ctr.clone());
        // Add your own echo and ready to the channel
        rbc_state.add_echo(beacon_msg.origin, self.myid, &ctr);
        rbc_state.add_ready(beacon_msg.origin, self.myid, &ctr);
        // Broadcast echos and benchmark results
        self.broadcast(CoinMsg::CTRBCEcho(ctr.clone(), ctr.mp.root(),self.myid),ctr.round).await;
        self.add_benchmark(String::from("process_batchwss_init"), now.elapsed().unwrap().as_nanos());
    }
}
