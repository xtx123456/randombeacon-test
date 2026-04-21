use std::time::SystemTime;

use crypto::hash::Hash;
use types::{beacon::CTRBCMsg, beacon::Replica};

use crate::node::{Context, CTRBCState};

impl Context {
    pub async fn process_reconstruct(&mut self, ctrbc: CTRBCMsg, master_root: Hash, recon_sender: Replica) {
        let _now = SystemTime::now();
        if !self.round_state.contains_key(&ctrbc.round) {
            let rbc_new_state = CTRBCState::new(self.secret_domain.clone(), self.num_nodes);
            self.round_state.insert(ctrbc.round, rbc_new_state);
        }
        let round = ctrbc.round;
        let rbc_state = self.round_state.get_mut(&ctrbc.round).unwrap();
        let sec_origin = ctrbc.origin;
        log::info!(
            "Received RECON message from {} for secret from {} in round {}",
            recon_sender,
            ctrbc.origin,
            ctrbc.round
        );

        if rbc_state.terminated_secrets.contains(&sec_origin) {
            log::info!("Batch secret instance from node {} already terminated", sec_origin);
            return;
        }
        if !rbc_state.msgs.contains_key(&sec_origin) {
            rbc_state.add_recon(sec_origin, recon_sender, &ctrbc);
            return;
        }
        let (_beacon, shard) = rbc_state.msgs.get(&sec_origin).unwrap();
        if shard.mp.root() != master_root || !ctrbc.verify_mr_proof(&self.hash_context) {
            log::error!(
                "Merkle root of WSS Init from {} did not match Merkle root of Recon from {}",
                sec_origin,
                self.myid
            );
            return;
        }
        rbc_state.add_recon(sec_origin, recon_sender, &ctrbc);
        let res_root_vec = rbc_state.verify_reconstruct_rbc(
            sec_origin,
            self.num_nodes,
            self.num_faults,
            self.batch_size,
            &self.hash_context,
        );
        match res_root_vec {
            None => return,
            Some(_res) => {
                rbc_state.transform(sec_origin);
                let term_secrets = rbc_state.terminated_secrets.len();
                let should_trigger_acs = term_secrets >= self.num_nodes - self.num_faults;
                let _ = rbc_state;
                if should_trigger_acs {
                    self.maybe_broadcast_acs_init_from_avss(round).await;
                }
            }
        }
    }
}
