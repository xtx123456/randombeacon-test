use std::{
    collections::HashSet,
    net::{SocketAddr, SocketAddrV4},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, Result};
use config::Node;
use crypto::aes_hash::HashState;
use fnv::FnvHashMap;
use fnv::FnvHashMap as HashMap;
use network::{
    plaintcp::{CancelHandler, TcpReceiver, TcpReliableSender},
    Acknowledgement,
};
use num_bigint::BigUint;
use tokio::{
    sync::{mpsc::unbounded_channel, mpsc::UnboundedReceiver, oneshot},
};

use types::{
    beacon::{CoinMsg, Replica, WrapperMsg},
    Round, SyncMsg, SyncState,
};

use super::{CTRBCState, Handler, SyncHandler};

/// Public, deterministic seed used to derive the round-0 degree-test
/// challenge θ. Every node uses this, so dealers and verifiers agree
/// without a previous beacon being available.
pub const PPT_GENESIS_THETA_SEED: &[u8] = b"PPT_BEACON_GENESIS_THETA_v1";

/// PPT random-beacon node context (pure-PPT mode: frequency φ = 1,
/// every honest node is always a dealer, no anytrust committee, no
/// legacy Binary-AA / Gather / CTRBC paths).
pub struct Context {
    // ---- Networking ----
    pub net_send: TcpReliableSender<Replica, WrapperMsg, Acknowledgement>,
    pub net_recv: UnboundedReceiver<WrapperMsg>,
    pub sync_send: TcpReliableSender<Replica, SyncMsg, Acknowledgement>,
    pub sync_recv: UnboundedReceiver<SyncMsg>,

    // ---- Identity / sizing ----
    pub num_nodes: usize,
    pub myid: usize,
    pub num_faults: usize,
    pub sec_key_map: HashMap<Replica, Vec<u8>>,

    // ---- Crypto context ----
    pub hash_context: HashState,
    pub secret_domain: BigUint,
    pub nonce_domain: BigUint,

    // ---- Round bookkeeping ----
    pub curr_round: u32,
    pub max_rounds: u32,
    pub batch_size: usize,
    /// Pure-PPT mode forces frequency φ = 1.
    pub frequency: Round,
    pub round_state: HashMap<Round, CTRBCState>,

    // ---- ACS state ----
    pub acs_state: std::collections::HashMap<Round, crate::node::acs::state::ACSInstanceState>,

    /// Round → degree-test challenge θ (large field). Populated when
    /// each round's beacon output is finalised; consumed by the next
    /// round's AVSS dealer / verifier path.
    pub theta_per_round: HashMap<Round, BigUint>,

    /// Globally banned dealers (across rounds). A dealer is banned
    /// the moment any honest node detects a protocol-level violation
    /// (invalid AVSS packet, equivocating ACS proposal,
    /// Merkle/commitment mismatch in the post-ACS audit). Once
    /// banned, the dealer is rejected from every future round's
    /// AVSS, ACS, and reconstruction paths.
    pub banned_dealers: HashSet<Replica>,

    // ---- Diagnostics / lifecycle ----
    pub num_messages: u32,
    pub bench: HashMap<String, u128>,
    pub cancel_handlers: HashMap<Round, Vec<CancelHandler<Acknowledgement>>>,
    exit_rx: oneshot::Receiver<()>,
}

impl Context {
    pub fn spawn(
        config: Node,
        _sleep: u128,
        batch: usize,
        frequency: Round,
    ) -> anyhow::Result<oneshot::Sender<()>> {
        let prot_payload = &config.prot_payload;
        let v: Vec<&str> = prot_payload.split(',').collect();

        let mut consensus_addrs: FnvHashMap<Replica, SocketAddr> = FnvHashMap::default();
        for (replica, address) in config.net_map.iter() {
            let address: SocketAddr = address.parse().expect("Unable to parse address");
            consensus_addrs.insert(*replica, SocketAddr::from(address));
        }

        let my_port = consensus_addrs.get(&config.id).unwrap();
        let my_address = to_socket_address("0.0.0.0", my_port.port());

        let mut syncer_map: FnvHashMap<Replica, SocketAddr> = FnvHashMap::default();
        syncer_map.insert(0, config.client_addr);

        let (tx_net_to_consensus, rx_net_to_consensus) = unbounded_channel();
        TcpReceiver::<Acknowledgement, WrapperMsg, _>::spawn(
            my_address,
            Handler::new(tx_net_to_consensus),
        );

        let syncer_listen_port = config.client_port;
        let syncer_l_address = to_socket_address("0.0.0.0", syncer_listen_port);

        let (tx_net_to_client, rx_net_from_client) = unbounded_channel();
        TcpReceiver::<Acknowledgement, SyncMsg, _>::spawn(
            syncer_l_address,
            SyncHandler::new(tx_net_to_client),
        );

        let consensus_net =
            TcpReliableSender::<Replica, WrapperMsg, Acknowledgement>::with_peers(
                consensus_addrs.clone(),
            );
        let sync_net =
            TcpReliableSender::<Replica, SyncMsg, Acknowledgement>::with_peers(syncer_map);

        if v[0] != "cc" {
            panic!("Invalid configuration for protocol");
        }

        let (exit_tx, exit_rx) = oneshot::channel();

        tokio::spawn(async move {
            let prime = BigUint::parse_bytes(b"685373784908497", 10).unwrap();
            let nonce_prime = BigUint::parse_bytes(
                b"57896044618658097711785492504343953926634992332820282019728792003956564819949",
                10,
            )
            .unwrap();

            let key0 = [5u8; 16];
            let key1 = [29u8; 16];
            let key2 = [23u8; 16];
            let hashstate = HashState::new(key0, key1, key2);

            let pure_ppt_frequency: Round = 1;
            if frequency != pure_ppt_frequency {
                log::warn!(
                    "[PPT][PURE] overriding requested frequency {} -> {}",
                    frequency,
                    pure_ppt_frequency
                );
            }

            let mut c = Context {
                net_send: consensus_net,
                net_recv: rx_net_to_consensus,
                sync_send: sync_net,
                sync_recv: rx_net_from_client,

                num_nodes: config.num_nodes,
                sec_key_map: HashMap::default(),
                myid: config.id,
                num_faults: config.num_faults,

                hash_context: hashstate,
                secret_domain: prime.clone(),
                nonce_domain: nonce_prime.clone(),

                curr_round: 0,
                max_rounds: 20000,
                batch_size: batch,
                frequency: pure_ppt_frequency,
                round_state: HashMap::default(),

                acs_state: std::collections::HashMap::new(),
                theta_per_round: HashMap::default(),
                banned_dealers: HashSet::new(),

                num_messages: 0,
                bench: HashMap::default(),
                cancel_handlers: HashMap::default(),
                exit_rx,
            };

            for (id, sk_data) in config.sk_map.clone() {
                c.sec_key_map.insert(id, sk_data.clone());
            }

            log::error!("[PPT] ppt_beacon context started on node {}", c.myid);
            log::error!("[PPT][ACS] quorum ACS engine loaded on node {}", c.myid);

            if let Err(e) = c.run().await {
                log::error!("[PPT] Consensus error: {}", e);
            }
        });

        Ok(exit_tx)
    }

    pub fn add_benchmark(&mut self, func: String, elapsed_time: u128) {
        if self.bench.contains_key(&func) {
            if *self.bench.get(&func).unwrap() < elapsed_time {
                self.bench.insert(func, elapsed_time);
            }
        } else {
            self.bench.insert(func, elapsed_time);
        }
    }

    /// Mark a dealer as banned and propagate to every live ACS
    /// instance.
    pub fn ban_dealer_global(&mut self, dealer: Replica) {
        if self.banned_dealers.insert(dealer) {
            log::error!(
                "[PPT][BAN] node {} permanently banning dealer {}",
                self.myid,
                dealer
            );
            for st in self.acs_state.values_mut() {
                st.ban_dealer(dealer);
            }
        }
    }

    pub fn permanently_banned_dealers(&self) -> HashSet<Replica> {
        self.banned_dealers.clone()
    }

    /// Locally AVSS-completed dealers for `round`, with banned
    /// dealers filtered out.
    pub fn local_completed_dealers(&self, round: Round) -> HashSet<Replica> {
        let banned = &self.banned_dealers;
        match self.round_state.get(&round) {
            Some(rbc_state) => rbc_state
                .avss_completed_dealers
                .iter()
                .copied()
                .filter(|d| !banned.contains(d))
                .collect(),
            None => HashSet::new(),
        }
    }

    /// θ for round `round` — the degree-test challenge that
    /// dealers commit to and verifiers re-evaluate. The PPT
    /// scheme requires θ to be unpredictable to the dealer at
    /// commit time. We therefore derive it from the *previous
    /// round's reconstructed beacon* (large field), which the
    /// dealer cannot influence by the time it shares its round-r
    /// secret.
    ///
    /// For round 0 we use a fixed public seed so all nodes agree
    /// without a previous beacon being available.
    pub fn theta_for_round(&self, round: Round) -> BigUint {
        if round == 0 {
            return Self::theta_from_bytes(PPT_GENESIS_THETA_SEED, &self.nonce_domain);
        }
        if let Some(theta) = self.theta_per_round.get(&round) {
            return theta.clone();
        }
        // Round-r dealer / verifier should always have round-(r-1)'s
        // beacon recorded before they touch this method. If not, we
        // refuse to fall back to a predictable value: returning a
        // distinguished sentinel θ would silently reintroduce the
        // hash(round) bug. Instead, we panic loudly so the bug is
        // caught in testing rather than reducing the security
        // parameter at runtime.
        panic!(
            "[PPT][THETA] round {} requested theta but no previous-round beacon recorded",
            round
        );
    }

    /// Record this round's beacon output as the source of the
    /// next round's degree-test challenge. `output_bytes` is the
    /// reconstructed beacon value (arbitrary-length); we hash it
    /// into the large field so θ has full large-field entropy
    /// rather than being constrained to the small secret field.
    pub fn record_beacon_output_for_theta(&mut self, round: Round, output_bytes: &[u8]) {
        let theta = Self::theta_from_bytes(output_bytes, &self.nonce_domain);
        self.theta_per_round.insert(round + 1, theta);
    }

    /// PPT slide pg 30-32 "first-match" rejection-sampling rule.
    ///
    /// A reconstructed coin value `v ∈ [0, p)` is *uniformly usable*
    /// as a sample in `[0, n)` (e.g. for BFT leader election) iff
    /// `v < n * floor(p / n)`. Coins outside the cutoff are biased
    /// and must be discarded by the consumer; the protocol picks the
    /// *first* coin (in batch order) that satisfies the rule.
    ///
    /// This helper just answers the boolean check; the iteration
    /// over the batch is done by the consumer (e.g. the syncer or a
    /// downstream BFT module) so that the protocol does not silently
    /// drop coins that some other consumer may still want for
    /// non-uniform purposes.
    pub fn coin_value_matches_uniform_range(&self, coin_bytes: &[u8]) -> bool {
        Self::coin_value_matches_uniform_range_with(
            coin_bytes,
            &self.secret_domain,
            self.num_nodes,
        )
    }

    pub(crate) fn theta_from_bytes(seed: &[u8], large_field: &BigUint) -> BigUint {
        // Wide-reduction so the result is statistically indistinguishable
        // from uniform in [0, q): hash twice and concatenate. This gives
        // 64 bytes of output ≫ |q| ≈ 32 bytes, then reduce mod q.
        let h1 = crypto::hash::do_hash(seed);
        let mut prefix = b"PPT_BEACON_THETA_v1::".to_vec();
        prefix.extend_from_slice(&h1);
        let h2 = crypto::hash::do_hash(prefix.as_slice());
        let mut wide = Vec::with_capacity(h1.len() + h2.len());
        wide.extend_from_slice(&h1);
        wide.extend_from_slice(&h2);
        BigUint::from_bytes_be(&wide) % large_field
    }

    /// Pure helper used by the first-match selector. Exposed for
    /// tests; production code goes through
    /// `coin_value_matches_uniform_range`.
    pub(crate) fn coin_value_matches_uniform_range_with(
        coin_bytes: &[u8],
        secret_domain: &BigUint,
        num_nodes: usize,
    ) -> bool {
        if num_nodes == 0 {
            return false;
        }
        let n = BigUint::from(num_nodes as u64);
        let cutoff: BigUint = (secret_domain / &n) * &n;
        let v = BigUint::from_bytes_be(coin_bytes);
        let v_mod = &v % secret_domain;
        v_mod < cutoff
    }

    /// Broadcast a message to all nodes.
    pub async fn broadcast(&mut self, protmsg: CoinMsg, round: Round) {
        let sec_key_map = self.sec_key_map.clone();
        for (replica, sec_key) in sec_key_map.into_iter() {
            if replica != self.myid {
                let wrapper_msg =
                    WrapperMsg::new(protmsg.clone(), self.myid, sec_key.as_slice(), round);
                let cancel_handler: CancelHandler<Acknowledgement> =
                    self.net_send.send(replica, wrapper_msg).await;
                self.add_cancel_handler(cancel_handler);
            }
        }
    }

    /// Cancel handler is a token to attempt repeated delivery of a message.
    pub fn add_cancel_handler(&mut self, canc: CancelHandler<Acknowledgement>) {
        self.cancel_handlers
            .entry(self.curr_round)
            .or_default()
            .push(canc);
    }

    /// Send a message to an individual node
    pub async fn send(&mut self, replica: Replica, wrapper_msg: WrapperMsg) {
        let cancel_handler: CancelHandler<Acknowledgement> =
            self.net_send.send(replica, wrapper_msg).await;
        self.add_cancel_handler(cancel_handler);
    }

    /// Main loop
    pub async fn run(&mut self) -> Result<()> {
        let cancel_handler = self
            .sync_send
            .send(
                0,
                SyncMsg {
                    sender: self.myid,
                    state: SyncState::ALIVE,
                    value: 0,
                },
            )
            .await;
        self.add_cancel_handler(cancel_handler);

        loop {
            tokio::select! {
                exit_val = &mut self.exit_rx => {
                    exit_val.map_err(anyhow::Error::new)?;
                    log::info!("Termination signal received by the server. Exiting.");
                    break;
                }
                msg = self.net_recv.recv() => {
                    let msg = msg.ok_or_else(|| anyhow!("Networking layer has closed"))?;
                    self.process_msg(msg).await;
                }
                sync_msg = self.sync_recv.recv() => {
                    let sync_msg = sync_msg.ok_or_else(|| anyhow!("Networking layer has closed"))?;
                    match sync_msg.state {
                        SyncState::START => {
                            log::error!(
                                "[PPT] Consensus Start time: {:?}",
                                SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap()
                                    .as_millis()
                            );
                            self.start_new_round(20000, Vec::new()).await;
                            let cancel_handler = self
                                .sync_send
                                .send(
                                    0,
                                    SyncMsg {
                                        sender: self.myid,
                                        state: SyncState::STARTED,
                                        value: 0,
                                    },
                                )
                                .await;
                            self.add_cancel_handler(cancel_handler);
                        }
                        SyncState::StartRecon => {
                            log::warn!(
                                "[PPT][SYNC-OFF] ignoring legacy StartRecon trigger; reconstruction now starts only after ACS finalization"
                            );
                        }
                        SyncState::STOP => {
                            log::error!(
                                "[PPT] Consensus Stop time: {:?}",
                                SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap()
                                    .as_millis()
                            );
                            log::info!("Termination signal received by the server. Exiting.");
                            break;
                        }
                        _ => {}
                    }
                }
            };
        }

        Ok(())
    }
}

pub fn to_socket_address(ip_str: &str, port: u16) -> SocketAddr {
    let addr = SocketAddrV4::new(ip_str.parse().unwrap(), port);
    addr.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    #[test]
    fn theta_is_in_large_field_and_uses_full_entropy() {
        // A small large field for testability.
        let q = BigUint::from(1_000_003u64);
        // Two distinct seeds must produce two distinct θ values
        // (probability of clash here is ~1/q which is well below the
        // statistical threshold for this test).
        let t1 = Context::theta_from_bytes(b"seed-A", &q);
        let t2 = Context::theta_from_bytes(b"seed-B", &q);
        assert!(t1 < q);
        assert!(t2 < q);
        assert_ne!(t1, t2);
    }

    #[test]
    fn theta_is_not_round_predictable() {
        // The buggy old implementation hashed only the round number,
        // so any honest seed-derivation with the SAME round produced
        // the same θ. The new implementation must take the full
        // beacon-output bytes into account.
        let q = BigUint::from(1_000_003u64);
        let beacon_a = b"\x00\x00\x00\x05BEACON_OUTPUT_A".to_vec();
        let beacon_b = b"\x00\x00\x00\x05BEACON_OUTPUT_B".to_vec();
        let theta_a = Context::theta_from_bytes(&beacon_a, &q);
        let theta_b = Context::theta_from_bytes(&beacon_b, &q);
        assert_ne!(theta_a, theta_b);
    }

    #[test]
    fn first_match_uniform_range_check() {
        // p = 11, n = 4 ⇒ cutoff = 4 * floor(11/4) = 4 * 2 = 8
        // values in [0, 8) accept; [8, 11) reject.
        let p = BigUint::from(11u32);
        for v in 0u32..8 {
            let bytes = BigUint::from(v).to_bytes_be();
            assert!(
                Context::coin_value_matches_uniform_range_with(&bytes, &p, 4),
                "v={} should match",
                v
            );
        }
        for v in 8u32..11 {
            let bytes = BigUint::from(v).to_bytes_be();
            assert!(
                !Context::coin_value_matches_uniform_range_with(&bytes, &p, 4),
                "v={} should NOT match",
                v
            );
        }
    }

    #[test]
    fn first_match_handles_oversized_input_via_mod_p() {
        let p = BigUint::from(11u32);
        // 19 mod 11 = 8, which is the rejection boundary.
        let bytes = BigUint::from(19u32).to_bytes_be();
        assert!(!Context::coin_value_matches_uniform_range_with(&bytes, &p, 4));
        // 18 mod 11 = 7, accepted.
        let bytes = BigUint::from(18u32).to_bytes_be();
        assert!(Context::coin_value_matches_uniform_range_with(&bytes, &p, 4));
    }
}
