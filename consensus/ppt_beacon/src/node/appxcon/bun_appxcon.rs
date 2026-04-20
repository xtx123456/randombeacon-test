use std::collections::HashMap;

use async_recursion::async_recursion;
use num_bigint::{BigUint};
use num_traits::pow;
use types::{Round, beacon::{Replica}};

use crate::node::Context;
/**
 * Phase 2 rewrite: Bundled Approximate Agreement.
 *
 * In the new design, frequency rounds use ACS-driven reconstruction
 * (handled in process.rs::process_acs_output). This module's
 * next_round_vals is retained for computing AA round values that
 * are bundled into the next BAwVSS message, but the old
 * "terminate beacon and start reconstruction" path is removed
 * for frequency rounds (ACS handles that now).
 *
 * Non-frequency rounds still use the bundled AA termination path
 * when bin_bun_aa is true.
 */
impl Context{
    #[async_recursion]
    pub async fn next_round_vals(&mut self, round:Round)->HashMap<Round,Vec<(Replica,BigUint)>>{
        if !self.round_state.contains_key(&round){
            return HashMap::default();
        }
        let rbc_state = self.round_state.get(&round).unwrap();
        let min_threshold = self.num_faults;
        let high_threshold = self.num_nodes-self.num_faults-1;

        let mut hmap:HashMap<Round,HashMap<Replica,Vec<BigUint>>> = HashMap::default();
        for node in 0..self.num_nodes{
            if rbc_state.appxcon_allround_vals.contains_key(&node){
                let values_replica = rbc_state.appxcon_allround_vals.get(&node).unwrap();
                for (round_i,vec_value) in values_replica.clone().into_iter(){
                    if hmap.contains_key(&round_i){
                        let index_map = hmap.get_mut(&round_i).unwrap();
                        for (appxcon_index,val) in vec_value.into_iter(){
                            if index_map.contains_key(&appxcon_index){
                                let vec_values_index = index_map.get_mut(&appxcon_index).unwrap();
                                vec_values_index.push(val);
                            }
                            else{
                                let mut vec_values_index:Vec<BigUint> = Vec::new();
                                vec_values_index.push(val);
                                index_map.insert(appxcon_index, vec_values_index);
                            }
                        }
                    }
                    else{
                        let mut index_map = HashMap::default();
                        for (appxcon_index,val) in vec_value.into_iter(){
                            let mut vec_values_index:Vec<BigUint> = Vec::new();
                            vec_values_index.push(val);
                            index_map.insert(appxcon_index, vec_values_index);
                        }
                        hmap.insert(round_i, index_map);
                    }
                }
            }
        }
        log::info!("Printing values init:{:?} final:{:?}",rbc_state.appxcon_allround_vals,hmap.clone());
        let mut return_map:HashMap<Round,Vec<(Replica,BigUint)>> = HashMap::default();
        let mut _term_rounds = Vec::new();
        for (round_iter,hmap_iter) in hmap.clone().into_iter(){
            log::info!("Appxcon indices for round {} in round {} are {:?} and values {:?}",round_iter,round,hmap_iter.keys(),hmap_iter);
            let mut index_returnval_vector = Vec::new();
            for (index,mut values) in hmap_iter.into_iter(){
                values.sort();
                let index_val:BigUint = (values[min_threshold].clone()+ values[high_threshold].clone())/2u32;
                index_returnval_vector.push((index,index_val));
            }
            // Track rounds that should terminate
            if round-round_iter-1 > self.rounds_aa{
                _term_rounds.push((round_iter,index_returnval_vector.clone()));
            }
            return_map.insert(round_iter, index_returnval_vector);
        }
        // Start new AA instance for frequency rounds
        if round%self.frequency == 0{
            let mut index_returnval_vector = Vec::new();
            for index in rbc_state.committee.clone().into_iter(){
                if !rbc_state.avss_completed_dealers.contains(&index) {
                    let zero = BigUint::from(0u32);
                    index_returnval_vector.push((index,zero));
                }
                else {
                    let max = BigUint::from(2u32);
                    let max_power = pow(max, self.rounds_aa as usize);
                    index_returnval_vector.push((index,max_power));
                }
            }
            return_map.insert(round, index_returnval_vector);
        }

        // Phase 2 change: For bundled AA mode, we NO LONGER trigger
        // reconstruction from here. ACS handles reconstruction for
        // frequency rounds. We only remove terminated rounds from
        // the return map so they don't get re-processed.
        if self.bin_bun_aa{
            for (term_round, _round_vecs) in _term_rounds.into_iter(){
                return_map.remove(&term_round);
                // Note: reconstruction is now handled by ACS in process_acs_output
                // We still need to clean up the return_map to avoid stale entries
            }
        }
        return return_map;
    }
}
