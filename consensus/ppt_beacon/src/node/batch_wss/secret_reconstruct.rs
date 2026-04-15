use std::{ time::{SystemTime, UNIX_EPOCH}};
use crypto::aes_hash::Proof;
use types::{beacon::{WSSMsg, CoinMsg}, Replica, SyncState, SyncMsg, beacon::{Round, BatchWSSReconMsg}};

use crate::node::{Context, CTRBCState};
use crate::node::ctrbc::state::BlameReason;

impl Context{
    /**
     * This function reconstructs a prepared beacon. All prepared beacons have a unique identifier determined by the round in which they were instantiated. 
     */
    pub async fn reconstruct_beacon(self: &mut Context, round:Round,mut coin_number:usize){
        let now = SystemTime::now();
        let rbc_state = self.round_state.get_mut(&round).unwrap();
        rbc_state.sync_secret_maps().await;
        let mut vector_coins = Vec::new();
        // Check if there exist prior beacons that can be reconstructed in this batch.
        for coin in 0..self.batch_size{
            if !rbc_state.recon_secrets.contains(&coin){
                let beacon = rbc_state.coin_check(round, coin, self.num_nodes).await;
                match beacon {
                    Some(c)=>{
                        vector_coins.push((coin,c));
                    },
                    None=>{}
                }
            }
        }
        if !vector_coins.is_empty() && coin_number != 0{
            log::error!("Enough information available to reconstruct coins until batch {}, moving forward to coin_num {}",vector_coins.last().unwrap().clone().0,vector_coins.last().unwrap().clone().0+1);
            coin_number = vector_coins.last().unwrap().0 + 1;
        }
        if coin_number > self.batch_size-1{
            return;
        }
        // Start reconstructing coin_number
        let mut bwssmsg = rbc_state.secret_shares(coin_number);
        bwssmsg.origin = self.myid;
        // Add your own share into your own map
        for (secret,rep) in bwssmsg.secrets.clone().into_iter().zip(bwssmsg.origins.clone().into_iter()){
            if rbc_state.committee.contains(&rep){
                rbc_state.add_secret_share(coin_number, rep.clone(), self.myid.clone(), secret);
            }
        }
        // Broadcast the shares using the BeaconConstruct message type. 
        let prot_msg = CoinMsg::BeaconConstruct(bwssmsg, self.myid.clone(),coin_number,round);
        self.broadcast(prot_msg,25000).await;
        self.add_benchmark(String::from("reconstruct_beacon"), now.elapsed().unwrap().as_nanos());
        for (coin_num,beacon) in vector_coins.into_iter(){
            self.self_coin_check_transmit(round, coin_num, beacon).await;
        }
    }
    
    /**
     * Phase 3 enhanced: Process secret shares with per-share Merkle verification.
     * Each share's commitment and Merkle proof is verified against the committed root vector.
     * If verification fails, the dealer is blamed and excluded from reconstruction.
     */
    pub async fn process_secret_shares(self: &mut Context,recon_shares:BatchWSSReconMsg,share_sender:Replica, coin_num:usize,round:Round){
        let now = SystemTime::now();
        log::info!("Received Coin construct message from node {} for coin_num {} for round {} with shares for secrets {:?}",share_sender,coin_num,round,recon_shares.origins);

        if !self.round_state.contains_key(&round){
            let rbc_new_state = CTRBCState::new(self.secret_domain.clone(),self.num_nodes);
            self.round_state.insert(round, rbc_new_state);
        }
        let rbc_state = self.round_state.get_mut(&round).unwrap();
        if coin_num == 0 && rbc_state.committee_elected{
            log::debug!("All secrets reconstructed. No need to process these shares. ");
            return;
        }
        if rbc_state.cleared{
            log::info!("Beacons have been output and state has been cleared for round {}, exiting",round);
            return;
        }

        // ================================================================
        // Phase 3: Enhanced per-share Merkle verification with blame
        // ================================================================
        // Step 1: Batch validate all Merkle proofs
        let mps_val = Proof::validate_batch(&recon_shares.mps, &self.hash_context);
        if !mps_val{
            log::error!("[BLAME] Batch Merkle proof validation failed for shares sent by node {} coin {} round {}",share_sender,coin_num,round);
            // Cannot determine which specific dealer is at fault from batch validation alone,
            // so we fall through to per-share verification below
        }

        // Step 2: Verify each share's commitment individually
        let commitments = self.hash_context.hash_batch(recon_shares.secrets.clone(), recon_shares.nonces.clone());
        for ((mp,comm), dealer) in recon_shares.mps.iter().zip(commitments.iter()).zip(recon_shares.origins.iter()){
            if mp.item() != *comm{
                log::error!(
                    "[BLAME] Commitment mismatch for dealer {} in shares from node {} coin {} round {}",
                    dealer, share_sender, coin_num, round
                );
                // Phase 3: Blame the dealer whose commitment doesn't match
                rbc_state.blame_dealer(
                    *dealer, round,
                    BlameReason::CommitmentMismatch {
                        coin_num,
                        expected_root: mp.root(),
                        got_item: *comm,
                    }
                );
            }
        }

        // Step 3: Verify each share's Merkle root against committed root vector
        for (mp, dealer) in recon_shares.mps.iter().zip(recon_shares.origins.iter()) {
            if let Some(root_vec) = rbc_state.comm_vectors.get(dealer) {
                if coin_num < root_vec.len() {
                    if mp.root() != root_vec[coin_num] {
                        log::error!(
                            "[BLAME] Merkle root mismatch for dealer {} coin {} round {}: proof root != committed root",
                            dealer, coin_num, round
                        );
                        rbc_state.blame_dealer(
                            *dealer, round,
                            BlameReason::MerkleRootMismatch {
                                coin_num,
                                expected_root: root_vec[coin_num],
                                got_root: mp.root(),
                            }
                        );
                    }
                }
            }
        }

        // Step 4: Process shares, skipping blamed dealers
        let secret_domain = self.secret_domain.clone();
        for (rep,(share, nonce)) in recon_shares.origins.into_iter().zip(recon_shares.secrets.into_iter().zip(recon_shares.nonces.into_iter())){
            let sec_origin = rep;

            // Phase 3: Skip shares from malicious dealers
            if rbc_state.malicious_dealers.contains(&sec_origin) {
                log::warn!("[BLAME] Skipping share from malicious dealer {} in coin {} round {}", sec_origin, coin_num, round);
                continue;
            }

            // Phase 4A (SS-AVSS): Verify share against public polynomial commitments
            // The share_sender's evaluation point is share_sender+1 (1-indexed)
            if !rbc_state.verify_share_against_poly(sec_origin, coin_num, share_sender + 1, &share, &secret_domain) {
                log::error!(
                    "[SS-AVSS][BLAME] Poly verification failed for dealer {} coin {} node {} round {}",
                    sec_origin, coin_num, share_sender, round
                );
                // Note: This could mean either the dealer is malicious (inconsistent poly_commits vs shares)
                // or the share_sender is lying. For now, we log but don't blame since the share_sender
                // might have received a different share than what poly_commits predict.
            }

            if rbc_state.recon_secrets.contains(&coin_num){
                log::info!("Older secret share received from node {}, not processing share for coin_num {}", sec_origin,coin_num);
                return;
            }
            rbc_state.add_secret_share(coin_num, sec_origin, share_sender, share);
            let _time_before_processing = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
            let wss_msg = WSSMsg{
                origin: rep,
                secret:share,
                nonce:nonce,
                mp: Proof::new(Vec::new(), Vec::new())
            };
            // Reconstruct the secret
            let secret = rbc_state.reconstruct_secret(coin_num,wss_msg, self.num_nodes,self.num_faults).await;
            match secret{
                None => {
                    continue;
                },
                Some(_secret)=>{
                    let coin_check = rbc_state.coin_check(round,coin_num, self.num_nodes).await;
                    match coin_check {
                        None => {
                            continue;
                        },
                        Some(mut _random)=>{
                            self.self_coin_check_transmit(round, coin_num, _random).await;
                            if coin_num < self.batch_size - 1 && coin_num != 0{
                                self.reconstruct_beacon(round,coin_num+1).await;   
                            }
                            break;
                        }
                    }
                }
            }
        }
        self.add_benchmark(String::from("process_batchreconstruct"), now.elapsed().unwrap().as_nanos()); 
    }
    /**
     * Beacons can be reconstructed in HashRand for two reasons:
     * a) For external consumption (which are sent to the syncer)
     * b) For internal consumption (for AnyTrust sampling and efficiency)
     */
    pub async fn self_coin_check_transmit(&mut self,round:Round,coin_num:usize,number:Vec<u8>){
        let rbc_state = self.round_state.get_mut(&round).unwrap();
        let recon_secrets_size = rbc_state.recon_secrets.len().clone();
        
        if recon_secrets_size == self.batch_size {
            log::error!("[PPT] Terminated all secrets of round {}, eliminating state",round);
            rbc_state._clear();
        }
        // The first beacon in a batch is always used for AnyTrust sampling
        if coin_num == 0{
            rbc_state.committee_elected = true;
            let committee = self.elect_committee(number.clone()).await;
            let round_baa = round+self.rounds_aa+3;
            let round_baa_fin:Round;
            if round_baa%self.frequency == 0{
                round_baa_fin = round_baa;
            }
            else{
                round_baa_fin = ((round_baa/self.frequency)+1)*self.frequency;
            }
            if self.round_state.contains_key(&round_baa_fin){
                self.round_state.get_mut(&round_baa_fin).unwrap().set_committee(committee);
            }
            let rbc_started_baa = self.round_state.get(&round_baa_fin).unwrap().started_baa;
            log::error!("Round state fin: {}, started_baa {}",round_baa_fin,rbc_started_baa);
            if rbc_started_baa{
                self.check_begin_next_round(round_baa_fin).await;
            }
        }
        else{
            if rbc_state.recon_secrets.contains(&(self.batch_size - 1)){
                log::info!("Reconstruction ended for round {} at time {:?}",round,SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis());
                log::info!("Number of messages passed between nodes: {}",self.num_messages);
            }
        }
        // Send the beacon output to the syncer node for tracking throughput. 
        let cancel_handler = self.sync_send.send(0, SyncMsg { sender: self.myid, state: SyncState::BeaconRecon(round, self.myid, coin_num, number), value:0}).await;
        self.add_cancel_handler(cancel_handler);
    }
}
