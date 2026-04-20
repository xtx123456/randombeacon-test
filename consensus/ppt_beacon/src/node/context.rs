use std::{
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

/// This artifact implements the PPT-style asynchronous random beacon path.
/// The current refactor explicitly runs in pure-PPT mode:
/// - frequency is forced to 1
/// - legacy Binary-AA is disabled on the main path
pub struct Context {
    /// Networking context
    pub net_send: TcpReliableSender<Replica, WrapperMsg, Acknowledgement>,
    pub net_recv: UnboundedReceiver<WrapperMsg>,
    pub sync_send: TcpReliableSender<Replica, SyncMsg, Acknowledgement>,
    pub sync_recv: UnboundedReceiver<SyncMsg>,

    /// Data context
    pub num_nodes: usize,
    pub myid: usize,
    pub num_faults: usize,
    pub payload: usize,

    /// Replica -> secret key
    pub sec_key_map: HashMap<Replica, Vec<u8>>,

    /// Hardware acceleration context
    pub hash_context: HashState,

    /// Secret-sharing domains
    pub secret_domain: BigUint,
    pub nonce_domain: BigUint,

    /// Approximate-agreement parameters inherited from the old codebase.
    /// They remain in the struct for compatibility, but the pure PPT path
    /// no longer uses Binary-AA as a live protocol path.
    pub rounds_aa: u32,
    pub epsilon: u32,

    pub curr_round: u32,
    pub recon_round: u32,

    /// Benchmarking
    pub num_messages: u32,
    pub max_rounds: u32,
    pub committee_size: usize,

    /// Batch size β in the paper
    pub batch_size: usize,

    /// Pure PPT mode forces frequency φ = 1.
    pub frequency: Round,

    /// Round state
    pub round_state: HashMap<Round, CTRBCState>,

    /// Benchmarking individual pieces
    pub bench: HashMap<String, u128>,

    /// Legacy switch kept only to avoid cascading type churn.
    pub bin_bun_aa: bool,

    /// Exit protocol
    exit_rx: oneshot::Receiver<()>,

    /// ACS local state
    pub acs_state: std::collections::HashMap<Round, crate::node::acs::state::ACSInstanceState>,

    /// Queue for future messages
    pub wrapper_msg_queue: HashMap<Round, Vec<WrapperMsg>>,

    /// Cancel handlers
    pub cancel_handlers: HashMap<Round, Vec<CancelHandler<Acknowledgement>>>,
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

        let committee_sizes: HashMap<usize, usize> = [
            (4, 3),
            (16, 11),
            (40, 27),
            (64, 43),
            (112, 49),
            (136, 51),
            (160, 54),
        ]
        .iter()
        .cloned()
        .collect();

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

            let epsilon: u32 = ((1024 * 1024) / (config.num_nodes * config.num_faults)) as u32;
            let rounds = (65.0 - ((epsilon as f32).log2().ceil())) as u32;

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

            log::error!("[PPT] Appx consensus rounds: {}", rounds);

            let mut c = Context {
                net_send: consensus_net,
                net_recv: rx_net_to_consensus,
                sync_send: sync_net,
                sync_recv: rx_net_from_client,

                num_nodes: config.num_nodes,
                sec_key_map: HashMap::default(),
                myid: config.id,
                num_faults: config.num_faults,
                payload: config.payload,

                hash_context: hashstate,
                secret_domain: prime.clone(),
                nonce_domain: nonce_prime.clone(),

                rounds_aa: rounds,
                epsilon,

                curr_round: 0,
                recon_round: 20000,

                num_messages: 0,
                max_rounds: 20000,

                bin_bun_aa: false,
                committee_size: *committee_sizes.get(&config.num_nodes).unwrap(),

                round_state: HashMap::default(),
                batch_size: batch,
                frequency: pure_ppt_frequency,
                bench: HashMap::default(),

                exit_rx,
                cancel_handlers: HashMap::default(),

                acs_state: std::collections::HashMap::new(),
                wrapper_msg_queue: HashMap::default(),
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

                    match &msg.protmsg {
                        CoinMsg::ACSInit((sender, round, dealers)) => {
                            log::error!(
                                "[PPT][ACS-INGRESS] node {} got wrapper ACSInit: payload-sender={} payload-round={} dealers={:?} wrapper-sender={} wrapper-round={}",
                                self.myid,
                                sender,
                                round,
                                dealers,
                                msg.sender,
                                msg.round
                            );
                        }
                        _ => {}
                    }

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
