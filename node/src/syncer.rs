use std::{collections::{HashSet, HashMap}, net::{SocketAddr,SocketAddrV4}, time::{SystemTime, UNIX_EPOCH, Duration}};

use anyhow::{Result, anyhow};
use beacon::node::num_bigint::BigInt;
use fnv::FnvHashMap;
use beacon::node::SyncHandler;
use network::{plaintcp::{TcpReceiver, TcpReliableSender, CancelHandler}, Acknowledgement};
use tokio::sync::{oneshot, mpsc::{unbounded_channel, UnboundedReceiver}};
use types::{Replica, SyncMsg, SyncState, beacon::Round};

pub struct Syncer{
    pub num_nodes: usize,
    pub start_time: u128,
    pub sharing_complete_times: HashMap<Replica,u128>,
    pub recon_start_time: u128,
    pub net_map: FnvHashMap<Replica,String>,
    pub alive: HashSet<Replica>,
    pub timings:HashMap<Replica,u128>,
    pub beacon_round_fin:HashMap<Round,HashMap<Replica,u128>>,
    pub beacon_recon_fin:HashMap<Round,HashMap<usize,HashMap<Replica,(u128,BigInt)>>>,
    pub values: HashMap<Replica,u64>,
    pub cli_addr: SocketAddr,
    pub rx_net: UnboundedReceiver<SyncMsg>,
    pub net_send: TcpReliableSender<Replica,SyncMsg,Acknowledgement>,
    exit_rx: oneshot::Receiver<()>,
    /// Cancel Handlers
    pub cancel_handlers: Vec<CancelHandler<Acknowledgement>>,

    /// ---- Beacon agreement diagnostics ----
    /// Tracks for each (round, coin) whether we've already emitted
    /// an [BEACON-AGREE] / [BEACON-DISAGREE] verdict line for it.
    /// `(round, coin) -> (agree_logged, disagree_logged)`.
    /// Disagreement always wins over agreement in the final counts:
    /// if AGREE is logged first and a late report later disagrees,
    /// we re-classify the (round, coin) as disagreed (and emit
    /// a DISAGREE line so the operator sees the late split).
    pub beacon_verdict_state: HashMap<(Round, usize), (bool, bool)>,
    /// Running totals across the whole run.
    pub agreed_coin_count: u64,
    pub disagreed_coin_count: u64,
}

impl Syncer{
    pub fn spawn(
        net_map: FnvHashMap<Replica,String>,
        cli_addr:SocketAddr,
    )-> anyhow::Result<oneshot::Sender<()>>{
        let (exit_tx, exit_rx) = oneshot::channel();
        let (tx_net_to_server, rx_net_to_server) = unbounded_channel();
        let cli_addr_sock = cli_addr.port();
        let new_sock_address = SocketAddrV4::new("0.0.0.0".parse().unwrap(), cli_addr_sock);
        TcpReceiver::<Acknowledgement, SyncMsg, _>::spawn(
            std::net::SocketAddr::V4(new_sock_address),
            SyncHandler::new(tx_net_to_server),
        );
        let mut server_addrs :FnvHashMap<Replica,SocketAddr>= FnvHashMap::default();
        println!("{:?}",net_map);
        for (replica,address) in net_map.iter(){
            let address:SocketAddr = address.parse().expect("Unable to parse address");
            server_addrs.insert(*replica, SocketAddr::from(address.clone()));
        }
        let net_send = TcpReliableSender::<Replica,SyncMsg,Acknowledgement>::with_peers(server_addrs);
        tokio::spawn(async move{
            let mut syncer = Syncer{
                net_map:net_map.clone(),
                start_time:0,
                sharing_complete_times:HashMap::default(),
                recon_start_time:0,
                num_nodes:net_map.len(),
                alive:HashSet::default(),
                values:HashMap::default(),
                timings:HashMap::default(),
                beacon_round_fin:HashMap::default(),
                beacon_recon_fin:HashMap::default(),
                cli_addr:cli_addr,
                rx_net:rx_net_to_server,
                net_send:net_send,
                exit_rx:exit_rx,
                cancel_handlers:Vec::new(),
                beacon_verdict_state: HashMap::default(),
                agreed_coin_count: 0,
                disagreed_coin_count: 0,
            };
            if let Err(e) = syncer.run().await {
                log::error!("Consensus error: {}", e);
            }
        });
        Ok(exit_tx)
    }
    pub async fn broadcast(&mut self, sync_msg:SyncMsg){
        for replica in 0..self.num_nodes {
            let cancel_handler:CancelHandler<Acknowledgement> = self.net_send.send(replica, sync_msg.clone()).await;
            self.add_cancel_handler(cancel_handler);    
        }
    }
    pub async fn run(&mut self)-> Result<()>{
        let mut beacons_count:u32 = 0;
        let time_start = 30000;
        let time_end = 90000;
        loop {
            tokio::select! {
                // Receive exit handlers
                exit_val = &mut self.exit_rx => {
                    exit_val.map_err(anyhow::Error::new)?;
                    log::error!("Termination signal received by the server. Exiting.");
                    // Final beacon-agreement totals (also printed every 100
                    // verdicts during the run via [BEACON-AGREE-PROGRESS]).
                    let total = self.agreed_coin_count + self.disagreed_coin_count;
                    let rate = if total > 0 {
                        100.0 * (self.disagreed_coin_count as f64) / (total as f64)
                    } else {
                        0.0
                    };
                    log::error!(
                        "[BEACON-AGREE-FINAL] total_verdicts={} agreed={} disagreed={} disagree_rate={:.4}%",
                        total, self.agreed_coin_count, self.disagreed_coin_count, rate
                    );
                    break
                },
                msg = self.rx_net.recv() => {
                    // Received a protocol message
                    // Received a protocol message
                    log::debug!("Got a message from the server: {:?}", msg);
                    let msg = msg.ok_or_else(||
                        anyhow!("Networking layer has closed")
                    )?;
                    match msg.state{
                        SyncState::ALIVE=>{
                            log::error!("Got ALIVE message from node {}",msg.sender);
                            self.alive.insert(msg.sender);
                            if self.alive.len() == self.num_nodes{
                                // sleep before sending message
                                std::thread::sleep(Duration::from_secs(3));
                                self.broadcast(SyncMsg { 
                                    sender: self.num_nodes, 
                                    state: SyncState::START,
                                    value:0
                                }).await;
                                self.start_time = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_millis();
                            }
                        },
                        SyncState::STARTED=>{
                            log::error!("Node {} started the protocol",msg.sender);
                        },
                        SyncState::CompletedSharing=>{
                            log::error!("Node {} completed the sharing phase of the protocol",msg.sender);
                            self.sharing_complete_times.insert(msg.sender, SystemTime::now().duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_millis());
                            self.values.insert(msg.sender,msg.value);
                            if self.sharing_complete_times.len() == (2*self.num_nodes/3)+1{
                                // All nodes terminated sharing protocol
                                let mut vec_times = Vec::new();
                                for (_rep,time) in self.sharing_complete_times.iter(){
                                    vec_times.push(time.clone()-self.start_time);
                                }
                                vec_times.sort();
                                log::error!("All n nodes completed the sharing protocol {:?} {:?}",vec_times,self.values);
                                self.start_time = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_millis(); 
                                self.broadcast(SyncMsg { sender: self.num_nodes, state: SyncState::StartRecon, value:0 }).await;
                            }
                        },
                        SyncState::CompletedRecon=>{
                            log::error!("Node {} completed the reconstruction phase of the protocol",msg.sender);
                            self.timings.insert(msg.sender, SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_millis());
                            if self.timings.len() == self.num_nodes{
                                // All nodes terminated protocol
                                let mut vec_times = Vec::new();
                                for (_rep,time) in self.timings.iter(){
                                    vec_times.push(time.clone()-self.start_time);
                                }
                                vec_times.sort();
                                log::error!("All n nodes completed the recon protocol {:?} {:?}",vec_times,self.values);
                                self.broadcast(SyncMsg { sender: self.num_nodes, state: SyncState::STOP, value:0}).await;
                            }
                        },
                        SyncState::BeaconFin(round,sender)=>{
                            log::debug!("Node {} completed the Beacon finish of the protocol for round {}",sender,round);
                            if !self.beacon_round_fin.contains_key(&round){
                                let val_map:HashMap<Replica, u128> = HashMap::default();
                                self.beacon_round_fin.insert(round,val_map);
                            }
                            let val_map = self.beacon_round_fin.get_mut(&round).unwrap();
                            val_map.insert(msg.sender, SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_millis());
                            // self.timings.insert(msg.sender, SystemTime::now()
                            // .duration_since(UNIX_EPOCH)
                            // .unwrap()
                            // .as_millis());
                            if val_map.len() == self.num_nodes{
                                // All nodes terminated protocol
                                let mut vec_times = Vec::new();
                                for (_rep,time) in val_map.iter(){
                                    vec_times.push(time.clone()-self.start_time);
                                }
                                vec_times.sort();
                                log::info!("All n nodes completed round {:?} {:?}",round,vec_times);
                                //self.broadcast(SyncMsg { sender: self.num_nodes, state: SyncState::STOP, value:0}).await;
                            }
                        },
                        SyncState::BeaconRecon(round,sender,index,secret)=>{
                            let big_int_sec = BigInt::from_signed_bytes_be(secret.as_slice());
                            if !self.beacon_recon_fin.contains_key(&round){
                                let mut val_map:HashMap<usize, HashMap<Replica,(u128,BigInt)>> = HashMap::default();
                                let mut rep_sec_map = HashMap::default();
                                rep_sec_map.insert(sender,(SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_millis(),big_int_sec));
                                val_map.insert(index,rep_sec_map);
                                self.beacon_recon_fin.insert(round,val_map);
                                continue;
                            }
                            let val_map = self.beacon_recon_fin.get_mut(&round).unwrap();
                            if !val_map.contains_key(&index){
                                let mut rep_sec_map = HashMap::default();
                                rep_sec_map.insert(sender,(SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_millis(),big_int_sec));
                                val_map.insert(index,rep_sec_map);
                                continue;
                            }
                            let time_sec_map = val_map.get_mut(&index).unwrap();
                            time_sec_map.insert(sender, (SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_millis(),big_int_sec));
                            
                            // self.timings.insert(msg.sender, SystemTime::now()
                            // .duration_since(UNIX_EPOCH)
                            // .unwrap()
                            // .as_millis());
                            if time_sec_map.len() == 2*self.num_nodes/3{
                                // All nodes terminated reconstruction protocol
                                let mut vec_times = Vec::new();
                                let mut set_map:HashSet<BigInt> = HashSet::default();
                                for (_rep,(time,secret)) in time_sec_map.iter(){
                                    let time_lat = time.clone()-self.start_time;
                                    if time_lat > time_start && time_lat < time_end{
                                        vec_times.push(time_lat);
                                    } 
                                    set_map.insert(secret.clone());
                                }
                                if set_map.len() == 1 && vec_times.len() == 2*self.num_nodes/3 {
                                    beacons_count +=1;
                                }
                                //vec_times.sort();
                                log::info!("All n nodes completed reconstruction for round {:?} and index {} with {:?},and set map : {:?}",round,index,vec_times, set_map);
                                //self.broadcast(SyncMsg { sender: self.num_nodes, state: SyncState::STOP, value:0}).await;
                            }

                            // ---- Beacon agreement diagnostic ----
                            // We compare beacon values reported by different nodes for
                            // the same (round, coin) and emit one AGREE / DISAGREE
                            // verdict line that the benchmark CSV parser can pick up.
                            //
                            // Trigger threshold: 2n/3 reports.
                            // This matches the existing `beacons_count`/`unique_beacon_count`
                            // threshold above (line 245) and is the correct quorum for
                            // n = 3f+1 anyway. Waiting for all n reports (the previous
                            // behaviour) almost never fires inside the 60 s benchmark
                            // window because the benchmark is killed before stragglers
                            // catch up, which is why prior CSV runs showed 0 verdicts.
                            //
                            // Disagreement ⇒ two honest nodes computed DIFFERENT
                            // beacons for the same (round, coin), i.e. an observable
                            // ACS Agreement violation in PPT. We log per-value node
                            // groupings so it's easy to tell which nodes split.
                            //
                            // Late-report upgrade: if we first logged AGREE at 2n/3 and
                            // a later straggler delivers a DIFFERENT value, we re-emit
                            // a DISAGREE line and re-classify the (round, coin) in the
                            // running totals (agree--, disagree++). This way a late
                            // network split is never silently swallowed.
                            let quorum = 2 * self.num_nodes / 3;
                            if time_sec_map.len() >= quorum {
                                let (agree_logged, disagree_logged) = self
                                    .beacon_verdict_state
                                    .get(&(round, index))
                                    .copied()
                                    .unwrap_or((false, false));

                                // Once we've already logged a DISAGREE for this coin
                                // we don't keep re-logging on every subsequent report.
                                if !disagree_logged {
                                    let mut by_value: HashMap<BigInt, Vec<Replica>> =
                                        HashMap::default();
                                    for (rep, (_t, secret)) in time_sec_map.iter() {
                                        by_value.entry(secret.clone()).or_default().push(*rep);
                                    }
                                    // Stable per-group node ordering for readable logs.
                                    for reps in by_value.values_mut() { reps.sort(); }

                                    if by_value.len() == 1 {
                                        // All reports so far agree. Emit AGREE only the
                                        // first time we cross the quorum threshold.
                                        if !agree_logged {
                                            self.agreed_coin_count += 1;
                                            self.beacon_verdict_state
                                                .insert((round, index), (true, false));
                                            let sample = by_value.keys().next().unwrap();
                                            let hex = sample.to_str_radix(16);
                                            let summary = if hex.len() > 24 {
                                                format!("{}...{} ({} hex chars)",
                                                    &hex[..8], &hex[hex.len()-8..], hex.len())
                                            } else {
                                                hex
                                            };
                                            log::info!(
                                                "[BEACON-AGREE] round {} index {} {}/{} nodes agree value={}",
                                                round, index, time_sec_map.len(), self.num_nodes, summary
                                            );
                                        }
                                    } else {
                                        // Disagreement observed. If we had previously
                                        // logged AGREE for this coin, reclassify the
                                        // running totals (agree--, disagree++).
                                        if agree_logged {
                                            if self.agreed_coin_count > 0 {
                                                self.agreed_coin_count -= 1;
                                            }
                                        }
                                        self.disagreed_coin_count += 1;
                                        self.beacon_verdict_state
                                            .insert((round, index), (agree_logged, true));

                                        // Print every distinct value with the node group
                                        // that reported it. Truncate value to first/last
                                        // 8 hex chars to keep the log line readable.
                                        let mut group_strs: Vec<String> = Vec::new();
                                        for (value, reps) in by_value.iter() {
                                            let hex = value.to_str_radix(16);
                                            let v_summary = if hex.len() > 24 {
                                                format!("{}...{}",
                                                    &hex[..8], &hex[hex.len()-8..])
                                            } else {
                                                hex
                                            };
                                            group_strs.push(format!(
                                                "nodes={:?}=>value={}", reps, v_summary));
                                        }
                                        let upgrade_tag = if agree_logged {
                                            " (upgraded from AGREE by late report)"
                                        } else {
                                            ""
                                        };
                                        log::error!(
                                            "[BEACON-DISAGREE] round {} index {} {} distinct beacon values across {}/{} reporting nodes{}; groups: [{}]",
                                            round, index, by_value.len(),
                                            time_sec_map.len(), self.num_nodes,
                                            upgrade_tag,
                                            group_strs.join(" | ")
                                        );
                                    }

                                    // Periodic progress so a long run shows running
                                    // totals without grep'ing the whole log.
                                    let total_verdicts =
                                        self.agreed_coin_count + self.disagreed_coin_count;
                                    if total_verdicts > 0 && total_verdicts % 100 == 0 {
                                        let rate = if total_verdicts > 0 {
                                            100.0 * (self.disagreed_coin_count as f64)
                                                / (total_verdicts as f64)
                                        } else {
                                            0.0
                                        };
                                        log::info!(
                                            "[BEACON-AGREE-PROGRESS] verdicts so far: agree={} disagree={} (disagree rate {:.4}%)",
                                            self.agreed_coin_count,
                                            self.disagreed_coin_count,
                                            rate
                                        );
                                    }
                                }
                            }
                            let current_time = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_millis();
                            if current_time - self.start_time > time_end{
                                log::error!("Beacons in 60 seconds: {} stopping protocol",beacons_count);
                                self.broadcast(SyncMsg { sender: self.num_nodes, state: SyncState::STOP, value:0}).await;
                            }
                        },
                        SyncState::COMPLETED=>{
                            log::error!("Got COMPLETED message from node {}",msg.sender);
                            self.timings.insert(msg.sender, SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_millis());
                            self.values.insert(msg.sender,msg.value);
                            if self.timings.len() == self.num_nodes{
                                // All nodes terminated protocol
                                let mut vec_times = Vec::new();
                                for (_rep,time) in self.timings.iter(){
                                    vec_times.push(time.clone()-self.start_time);
                                }
                                vec_times.sort();
                                //log::error!("All n nodes completed the protocol {:?} with values {:?}",vec_times,self.values);
                                self.broadcast(SyncMsg { sender: self.num_nodes, state: SyncState::STOP, value:0}).await;
                            }
                        }
                        _=>{}
                    }
                },
            }
        }
        Ok(())
    }
    pub fn add_cancel_handler(&mut self, canc: CancelHandler<Acknowledgement>){
        self.cancel_handlers
            .push(canc);
    }
}