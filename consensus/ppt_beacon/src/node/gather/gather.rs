use std::time::SystemTime;

use async_recursion::async_recursion;
use num_bigint::BigUint;
use num_traits::FromPrimitive;
use types::{
    beacon::{CoinMsg, GatherMsg},
    Replica, Round,
};

use crate::node::{Context, CTRBCState};

impl Context {
    pub async fn process_gatherecho(
        self: &mut Context,
        wss_indices: Vec<Replica>,
        echo_sender: Replica,
        round: u32,
    ) {
        let now = SystemTime::now();

        if !self.round_state.contains_key(&round) {
            let rbc_new_state = CTRBCState::new(BigUint::from_u16(0u16).unwrap(), self.num_nodes);
            self.round_state.insert(round, rbc_new_state);
        }

        let rbc_state = self.round_state.get_mut(&round).unwrap();

        log::info!(
            "[PPT][GATHER] Received W1 from node {} for round {} with {:?}",
            echo_sender,
            round,
            wss_indices
        );

        if rbc_state.send_w2 {
            log::debug!(
                "[PPT][LATE-W1] dropping late W1 from node {} for round {} because local state already moved to W2",
                echo_sender,
                round
            );
            return;
        }

        rbc_state.witness1.insert(echo_sender, wss_indices);

        self.add_benchmark(
            String::from("process_gatherecho"),
            now.elapsed().unwrap().as_nanos(),
        );

        self.witness_check(round).await;
    }

    pub async fn process_gatherecho2(
        self: &mut Context,
        wss_indices: Vec<Replica>,
        echo_sender: Replica,
        round: u32,
    ) {
        let now = SystemTime::now();

        if !self.round_state.contains_key(&round) {
            let rbc_new_state = CTRBCState::new(BigUint::from_u16(0u16).unwrap(), self.num_nodes);
            self.round_state.insert(round, rbc_new_state);
        }

        let rbc_state = self.round_state.get_mut(&round).unwrap();

        log::info!(
            "[PPT][GATHER] Received W2 from node {} for round {} with {:?}",
            echo_sender,
            round,
            wss_indices
        );

        rbc_state.witness2.insert(echo_sender, wss_indices);

        self.add_benchmark(
            String::from("process_gatherecho"),
            now.elapsed().unwrap().as_nanos(),
        );

        self.witness_check(round).await;
    }

    #[async_recursion]
    pub async fn witness_check(self: &mut Context, round: Round) {
        if !self.round_state.contains_key(&round) {
            return;
        }

        let mut msgs_to_be_sent: Vec<CoinMsg> = Vec::new();
        let quorum = self.num_nodes - self.num_faults;

        {
            let rbc_state = self.round_state.get_mut(&round).unwrap();

            let mut satisfied = 0usize;

            if !rbc_state.send_w2 {
                for (_replica, ss_inst) in rbc_state.witness1.clone().into_iter() {
                    let check = ss_inst
                        .iter()
                        .all(|item| rbc_state.terminated_secrets.contains(item));
                    if check {
                        satisfied += 1;
                    }
                }

                if satisfied >= quorum {
                    log::info!(
                        "[PPT][GATHER] round {} W1 complete, local dealers = {:?}",
                        round,
                        rbc_state.terminated_secrets.clone()
                    );

                    // Pure PPT path: always advance to W2 once W1 reaches quorum.
                    if !rbc_state.send_w2 {
                        log::info!(
                            "[PPT][PURE] round {} W1 quorum reached, sending W2 from node {}",
                            round,
                            self.myid
                        );

                        rbc_state.send_w2 = true;

                        msgs_to_be_sent.push(CoinMsg::GatherEcho2(
                            GatherMsg {
                                nodes: rbc_state
                                    .terminated_secrets
                                    .clone()
                                    .into_iter()
                                    .collect(),
                            },
                            self.myid,
                            round,
                        ));
                    }
                }
            } else {
                for (_replica, ss_inst) in rbc_state.witness2.clone().into_iter() {
                    let check = ss_inst
                        .iter()
                        .all(|item| rbc_state.terminated_secrets.contains(item));
                    if check {
                        satisfied += 1;
                    }
                }

                if satisfied >= quorum && !rbc_state.ppt_acs_init_sent {
                    let acs_dealers: Vec<Replica> =
                        rbc_state.terminated_secrets.clone().into_iter().collect();

                    log::error!(
                        "[PPT][ACS-TRIGGER] node {} round {} W2 complete, broadcasting ACSInit with {} dealers",
                        self.myid,
                        round,
                        acs_dealers.len()
                    );

                    msgs_to_be_sent.push(CoinMsg::ACSInit((self.myid, round, acs_dealers)));
                    rbc_state.ppt_acs_init_sent = true;
                }
            }
        }

        for prot_msg in msgs_to_be_sent.iter() {
            self.broadcast(prot_msg.clone(), round).await;

            match prot_msg {
                CoinMsg::GatherEcho2(gather, echo_sender, round_msg) => {
                    self.process_gatherecho2(gather.nodes.clone(), *echo_sender, *round_msg)
                        .await;
                }
                CoinMsg::ACSInit((sender, round_msg, dealers)) => {
                    self.process_acs_init(*sender, *round_msg, dealers.clone())
                        .await;
                }
                _ => {}
            }
        }
    }
}