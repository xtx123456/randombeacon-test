use std::{time::{SystemTime}, collections::HashMap};

use async_recursion::async_recursion;
use types::{beacon::{ CoinMsg, Round}, Replica};

use crate::node::{Context, CTRBCState, appxcon::RoundState};

/**
 * Phase 2 rewrite: Binary Approximate Agreement.
 *
 * Binary AA is retained for non-frequency rounds where lightweight
 * consensus is needed. For frequency rounds, ACS-driven reconstruction
 * (in process.rs) handles beacon finalization.
 *
 * Key change in next_round_begin: the old path that terminated beacons
 * and called reconstruct_beacon is removed. Frequency-round reconstruction
 * is now exclusively handled by ACS.
 */
impl Context{
    #[async_recursion]
    pub async fn process_baa_echo(self: &mut Context, msgs: Vec<(Round,Vec<(Replica,Vec<u8>)>)>, echo_sender:Replica, round:Round){
        let now = SystemTime::now();
        let mut send_valmap_echo1:HashMap<u32, Vec<(Replica, Vec<u8>)>> = HashMap::default();
        let mut send_valmap_echo2:HashMap<u32, Vec<(Replica, Vec<u8>)>> = HashMap::default();
        if round < self.curr_round{
            log::warn!("Older message received, protocol advanced forward, ignoring Binary AA ECHO message");
            return;
        }
        log::info!("Received ECHO1 message from node {} with content {:?} for round {}",echo_sender,msgs,round);
        for (round_iter,values) in msgs.into_iter(){
            if !self.round_state.contains_key(&round_iter){
                let rbc_new_state = CTRBCState::new(self.secret_domain.clone(),self.num_nodes);
                self.round_state.insert(round_iter, rbc_new_state);
            }
            let rbc_state = self.round_state.get_mut(&round_iter).unwrap();
            if rbc_state.round_state.contains_key(&round){
                let rnd_state = rbc_state.round_state.get_mut(&round).unwrap();
                let (echo1_msgs,echo2_msgs) = rnd_state.add_echo(values, echo_sender, self.num_nodes, self.num_faults);
                if rnd_state.term_vals.len() == rbc_state.committee.len() {
                    log::info!("All instances of Binary AA terminated for round {}, checking for termination related to round {}",round,round_iter);
                    if self.check_termination(round){
                        self.next_round_begin(round).await;
                    }
                    return;
                }
                if echo1_msgs.len() > 0{
                    send_valmap_echo1.insert(round_iter, echo1_msgs);
                }
                if echo2_msgs.len() > 0{
                    send_valmap_echo2.insert(round_iter, echo2_msgs);
                }
            }
            else{
                let rnd_state  = RoundState::new_with_echo(values,echo_sender);
                rbc_state.round_state.insert(round, rnd_state);
            }
            self.add_benchmark(String::from("process_baa_echo"), now.elapsed().unwrap().as_nanos());
        }
        if send_valmap_echo1.len() > 0{
            let mut vec_transmit = Vec::new();
            for (round,val_map) in send_valmap_echo1.into_iter(){
                vec_transmit.push((round,val_map));
            }
            self.broadcast(CoinMsg::BinaryAAEcho(vec_transmit.clone(), self.myid, round),round).await;
            self.process_baa_echo(vec_transmit, self.myid, round).await;
        }
        if send_valmap_echo2.len() > 0{
            let mut vec_transmit = Vec::new();
            for (round,val_map) in send_valmap_echo2.into_iter(){
                vec_transmit.push((round,val_map));
            }
            self.broadcast(CoinMsg::BinaryAAEcho2(vec_transmit.clone(), self.myid, round),round).await;
            self.process_baa_echo2(vec_transmit, self.myid, round).await;
        }
    }

    pub async fn process_baa_echo2(self: &mut Context, msgs: Vec<(Round,Vec<(Replica,Vec<u8>)>)>, echo2_sender:Replica, round:u32){
        let now = SystemTime::now();
        if round < self.curr_round{
            log::warn!("Older message received, protocol advanced forward, ignoring Binary AA ECHO message");
            return;
        }
        for (round_iter,vals) in msgs.into_iter(){
            if !self.round_state.contains_key(&round_iter){
                let rbc_new_state = CTRBCState::new(self.secret_domain.clone(),self.num_nodes);
                self.round_state.insert(round_iter, rbc_new_state);
            }
            let rbc_state = self.round_state.get_mut(&round_iter).unwrap();
            if rbc_state.round_state.contains_key(&round){
                let rnd_state = rbc_state.round_state.get_mut(&round).unwrap();
                rnd_state.add_echo2(vals, echo2_sender, self.num_nodes, self.num_faults);
                if rnd_state.term_vals.len() == rbc_state.committee.len() {
                    log::info!("All n instances of Binary AA terminated for round {} related to WSSInit {}",round,round_iter);
                    self.add_benchmark(String::from("process_baa_echo2"), now.elapsed().unwrap().as_nanos());
                    if self.check_termination(round){
                        self.next_round_begin(round).await;
                    }
                }
            }
            else{
                let rnd_state  = RoundState::new_with_echo2(vals,echo2_sender);
                rbc_state.round_state.insert(round, rnd_state);
            }
        }
    }

    fn check_termination(&mut self, r0:Round)->bool{
        let round_begin;
        if self.curr_round > r0{
            return false;
        }
        
        if r0 <= self.rounds_aa + 1{
            round_begin = 0;
        }
        else{
            round_begin = r0-self.rounds_aa-1;
        }
        let mut can_begin_next_round = true;
        for round_iter in round_begin..r0+1{
            if self.round_state.contains_key(&round_iter){
                let rbc_state = self.round_state.get(&round_iter).unwrap();
                if rbc_state.round_state.contains_key(&r0){
                    if rbc_state.round_state.get(&r0).unwrap().term_vals.len() < rbc_state.committee.len(){
                        log::info!("Cannot begin next BinAA round because BinAA of BAwVSS instantiated in round {} did not terminate round {}, term vals: {:?}",round_iter,r0,rbc_state.round_state.get(&r0).unwrap().term_vals);
                        can_begin_next_round = false;
                    }
                }
                else {
                    log::info!("Cannot begin next BinAA round because BinAA of BAwVSS instantiated in round {} does not have state for round {}",round_iter,r0);
                    can_begin_next_round = false;
                }
            }
        }
        can_begin_next_round
    }

    /// Phase 2 change: next_round_begin no longer triggers reconstruction
    /// for frequency rounds. That is handled by ACS in process_acs_output.
    /// This function only handles Binary AA round progression.
    #[async_recursion]
    pub async fn next_round_begin(&mut self,round:Round){
        let round_begin;
        if self.curr_round > round{
            return;
        }
        if round <= self.rounds_aa + 1{
            round_begin = 0;
        }
        else{
            round_begin = round-self.rounds_aa-1;
        }
        let mut vec_newround_vals = Vec::new();
        for round_iter in round_begin..round+1{
            if self.round_state.contains_key(&round_iter){
                let rbc_state = self.round_state.get(&round_iter).unwrap();
                if rbc_state.round_state.contains_key(&round){
                    let mut vec_replica_vals = Vec::new();
                    for (rep,value) in rbc_state.round_state.get(&round).unwrap().term_vals.clone().into_iter(){
                        vec_replica_vals.push((rep,value));
                    }
                    vec_newround_vals.push((round_iter,vec_replica_vals));
                }
            }
        }
        if round_begin > 1{
            log::info!("Round_Begin : {}, round state keys: {:?}, keys : {:?}",round_begin,self.round_state.keys(),self.round_state.get(&0).unwrap().round_state.keys());
        }
        else{
            log::info!("Round_Begin : {}, round state keys: {:?},  keys : {:?}",round_begin,self.round_state.keys(),self.round_state.get(&0).unwrap().round_state.keys());
        }

        // Phase 2 change: Do NOT trigger reconstruction from Binary AA.
        // ACS handles reconstruction for frequency rounds.
        // We only log that the round would have been terminated.
        if round_begin >= 1 && self.round_state.contains_key(&(round_begin-1)) && self.round_state.get(&(round_begin-1)).unwrap().round_state.contains_key(&(round-1)){
            log::info!("[PPT][BAA-SKIP] Binary AA would terminate round {} but ACS handles reconstruction", round_begin-1);
            // Note: reconstruction is now handled by ACS in process_acs_output
        }

        // Continue to next round
        if (round+1) % self.frequency == 0{
            self.start_new_round(round, vec_newround_vals).await;
        }
        else{
            let vec_round_msgs:Vec<(Round,Vec<(Replica,Vec<u8>)>)> = vec_newround_vals.into_iter().map(|(x,y)| {
                let mut msgs_vec = Vec::new();
                for (rep,val) in y.into_iter(){
                    msgs_vec.push((rep,val.to_bytes_be().to_vec()));
                }
                return (x,msgs_vec);
            }).collect();

            let prot_msg = CoinMsg::BinaryAAEcho(vec_round_msgs.clone(), self.myid, round+1);
            self.broadcast(prot_msg.clone(),round+1).await;
            self.process_baa_echo(vec_round_msgs, self.myid, round+1).await;
            self.increment_round(round).await;
            log::info!("[PPT][BAA] Started round {} with Binary AA",round+1);
        }
    }
}
