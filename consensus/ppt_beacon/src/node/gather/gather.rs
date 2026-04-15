use std::{time::SystemTime, collections::HashMap};

use async_recursion::async_recursion;
use num_bigint::{BigUint};
use num_traits::{FromPrimitive};
use types::{beacon::{CoinMsg}, Replica, Round, beacon::GatherMsg};

use crate::node::{Context, CTRBCState, RoundState};
/**
 * Phase 2 rewrite: Gather protocol with ACS-driven reconstruction.
 *
 * Control flow:
 * - W1 (GatherEcho): nodes broadcast their terminated_secrets set after n-f RBCs complete
 * - W2 (GatherEcho2): on frequency rounds, nodes broadcast again after accepting n-f W1s
 * - After n-f W2s accepted: broadcast ACSInit → ACS decides → reconstruction
 *
 * For non-frequency rounds: still use Binary AA (lightweight path)
 * For frequency rounds: ACS decision directly drives reconstruction (new fast path)
 */
impl Context {
    pub async fn process_gatherecho(self: &mut Context,wss_indices:Vec<Replica>, echo_sender:Replica,round: u32){
        let now = SystemTime::now();
        if !self.round_state.contains_key(&round){
            let rbc_new_state = CTRBCState::new(BigUint::from_u16(0u16).unwrap(),self.num_nodes);
            self.round_state.insert(round, rbc_new_state);
        }
        let rbc_state = self.round_state.get_mut(&round).unwrap();
        log::info!("[PPT][GATHER] Received W1 from node {} for round {} with {:?}",echo_sender,round,wss_indices);
        if rbc_state.send_w2{
            log::warn!("Ignoring echo1 because protocol moved forward to echo2s");
            return;
        }
        else {
            rbc_state.witness1.insert(echo_sender, wss_indices);
            self.add_benchmark(String::from("process_gatherecho"), now.elapsed().unwrap().as_nanos());
            self.witness_check(round).await;
        }
    }

    pub async fn process_gatherecho2(self: &mut Context,wss_indices:Vec<Replica>, echo_sender:Replica,round: u32){
        let now = SystemTime::now();
        if !self.round_state.contains_key(&round){
            let rbc_new_state = CTRBCState::new(BigUint::from_u16(0u16).unwrap(),self.num_nodes);
            self.round_state.insert(round, rbc_new_state);
        }
        let rbc_state = self.round_state.get_mut(&round).unwrap();
        log::info!("[PPT][GATHER] Received W2 from node {} for round {} with {:?}",echo_sender,round,wss_indices);
        rbc_state.witness2.insert(echo_sender, wss_indices);
        self.add_benchmark(String::from("process_gatherecho"), now.elapsed().unwrap().as_nanos());
        self.witness_check(round).await;
    }
    
    #[async_recursion]
    pub async fn witness_check(self: &mut Context,round:Round){
        let _now = SystemTime::now();
        if !self.round_state.contains_key(&round){
            return;
        }
        let rbc_state = self.round_state.get_mut(&round).unwrap();
        let mut i = 0;
        let mut msgs_to_be_sent:Vec<CoinMsg> = Vec::new();
        if !rbc_state.send_w2{
            // Count how many W1 witnesses are fully validated
            for (_replica,ss_inst) in rbc_state.witness1.clone().into_iter(){
                let check = ss_inst.iter().all(|item| rbc_state.terminated_secrets.contains(item));
                if check {
                    i = i+1;
                }
            }
            if i >= self.num_nodes-self.num_faults{
                log::info!("[PPT][GATHER] round {} W1 complete, local dealers = {:?}", round, rbc_state.terminated_secrets.clone());
                if round%self.frequency == 0{
                    // Frequency round: send W2 then proceed to ACS
                    log::info!("[PPT][GATHER] Frequency round {}, sending W2 from node {}",round,self.myid);
                    rbc_state.send_w2 = true;
                    msgs_to_be_sent.push(CoinMsg::GatherEcho2(
                        GatherMsg{nodes: rbc_state.terminated_secrets.clone().into_iter().collect()},
                        self.myid,
                        round)
                    );
                }
                else{
                    // Non-frequency round: use Binary AA (lightweight path, unchanged)
                    if !rbc_state.started_baa && self.bin_bun_aa{
                        rbc_state.started_baa = true;
                        self.check_begin_next_round(round).await;
                    }
                }
            }
        }
        else{
            // W2 phase: count accepted W2 witnesses
            for (_replica,ss_inst) in rbc_state.witness2.clone().into_iter(){
                let check = ss_inst.iter().all(|item| rbc_state.terminated_secrets.contains(item));
                if check {
                    i = i+1;
                }
            }    
            if i >= self.num_nodes-self.num_faults && !rbc_state.started_baa{
                // ============================================================
                // PHASE 2 CORE CHANGE: After n-f W2s, broadcast ACSInit
                // ACS will decide the final dealer set and drive reconstruction
                // directly via process_acs_output (see process.rs)
                // ============================================================
                let acs_dealers: Vec<Replica> = rbc_state.terminated_secrets.clone().into_iter().collect();
                log::error!("[PPT][ACS-TRIGGER] node {} round {} W2 complete, broadcasting ACSInit with {} dealers",
                    self.myid, round, acs_dealers.len());
                msgs_to_be_sent.push(CoinMsg::ACSInit((self.myid, round, acs_dealers.clone())));
                rbc_state.started_baa = true;

                // Handle committee election for future rounds
                if round >= self.rounds_aa+3{
                    let closest_finished = round-self.rounds_aa-3;
                    let fin_freq = (closest_finished/self.frequency)*self.frequency;
                    log::info!("Requesting beacon for committee election for round {:?} with coin from round {}",round,fin_freq);
                    if rbc_state.committee.len()<self.num_nodes{
                        // Committee already elected, proceed
                        self.check_begin_next_round(round).await;
                    }
                    else {
                        self.reconstruct_beacon(fin_freq, 0).await;   
                    }
                }
                else{
                    self.check_begin_next_round(round).await;
                }
            }
        }
        for prot_msg in msgs_to_be_sent.iter(){
            self.broadcast(prot_msg.clone(),round.clone()).await;
            match prot_msg {
                CoinMsg::GatherEcho2(gather, echo_sender,round) =>{
                    self.process_gatherecho2(gather.nodes.clone(), echo_sender.clone(), round.clone()).await;
                },
                CoinMsg::ACSInit((sender, round, dealers)) => {
                    self.process_acs_init(sender.clone(), round.clone(), dealers.clone()).await;
                },
                _ => {}
            }
        }
    }

    /// check_begin_next_round: orchestrates the transition to the next protocol round.
    /// For bundled AA: collects next_round_vals and starts new round.
    /// For binary AA: creates round states and begins next BAA round.
    pub async fn check_begin_next_round(&mut self,round: u32){
        let appxcon_vals_fin:HashMap<Round,Vec<(Replica,BigUint)>> = self.next_round_vals(round).await;
        if !appxcon_vals_fin.is_empty(){
            if self.bin_bun_aa{
                let mut vec_round_vals = Vec::new();
                for (round,values) in appxcon_vals_fin.into_iter(){
                    vec_round_vals.push((round,values));
                }
                self.start_new_round(round,vec_round_vals).await;
            }
            else{
                for (round_iter,values) in appxcon_vals_fin.into_iter(){
                    let rbc_state_iter = self.round_state.get_mut(&round_iter).unwrap();
                    let mut round_state = RoundState::new_with_echo(Vec::new(), self.myid);
                    for (rep,value) in values.into_iter(){
                        round_state.term_vals.insert(rep, value);
                    }
                    rbc_state_iter.round_state.insert(round, round_state);
                }
                self.next_round_begin(round).await;
            }
        }
    }
}
