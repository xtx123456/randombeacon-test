use std::{
    collections::HashSet,
    net::{SocketAddr, SocketAddrV4},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, Result};
use config::Node;
use crypto::aes_hash::HashState;
use crypto::gf2::Gf2Profile;
use crypto::hash::Hash;
use fnv::FnvHashMap;
use fnv::FnvHashMap as HashMap;
use network::{
    plaintcp::{CancelHandler, TcpReceiver, TcpReliableSender},
    Acknowledgement,
};
use num_bigint::BigUint;
use tokio::sync::{mpsc, oneshot};

/// Bounded inbound channel capacity.
///
/// Replaces the original `unbounded_channel`. Bounded queues apply
/// backpressure: when this node's consensus task can't keep up with
/// the inbound rate, `Sender::send().await` blocks instead of growing
/// unbounded memory; that backpressure propagates back to the TCP
/// kernel buffer of the peer, which naturally throttles the sender.
///
/// Picked so that one round's-worth of n=64 broadcasts (~64 * 8 ≈ 512
/// messages) easily fits even at high batch sizes, but a single slow
/// task can't accumulate more than ~16 round-equivalents before
/// senders start to block.
pub const PPT_INBOUND_CHANNEL_CAPACITY: usize = 8192;

use types::{
    beacon::{CoinMsg, Replica, WrapperMsg},
    Round, SyncMsg, SyncState,
};

use super::{CTRBCState, Handler, SyncHandler};

/// Public, deterministic seed used to derive the round-0 degree-test
/// challenge θ. Every node uses this, so dealers and verifiers agree
/// without a previous beacon being available.
pub const PPT_GENESIS_THETA_SEED: &[u8] = b"PPT_BEACON_GENESIS_THETA_v1";

/// Re-export `Gf2Profile` so that crates which depend on
/// `ppt_beacon` (e.g. `node`) do not need a direct `crypto`
/// dependency just to refer to the profile type.
pub use crypto::gf2::Gf2Profile as ExportedGf2Profile;

/// CLI-side parser for `--field "GF2(w_p,w_q)"`.
///
/// Thin wrapper around `Gf2Profile::from_str`, intentionally
/// returning an owned `String` error so callers can propagate it
/// directly to clap / panic / log without pulling in
/// `crypto::gf2::profile`'s error type. The helper lives here (and
/// not in `crypto::gf2`) so that the `node` binary stays
/// `crypto`-independent: it talks only to `ppt_beacon`.
///
/// Examples
/// --------
///
/// ```text
///     parse_field_spec("GF2(64,256)")  // Ok
///     parse_field_spec("(32, 128)")    // Ok
///     parse_field_spec("64,128")       // Ok
///     parse_field_spec("GF2(7,64)")    // Err — unregistered w_p
///     parse_field_spec("GF2(64,96)")   // Err — w_p ∤ w_q
/// ```
pub fn parse_field_spec(s: &str) -> Result<ExportedGf2Profile, String> {
    s.parse::<ExportedGf2Profile>()
}

/// Number of extra "coin secrets" each dealer seals per round, on top
/// of the `batch_size` beacon coins, to drive the next round's ACS
/// common coin (PPT problem-1 fix). These occupy batch coin indices
/// `[batch_size, batch_size + PPT_COIN_RESERVE)`; they are shared and
/// validated like beacon coins but are NEVER reconstructed/emitted as
/// beacon output — they stay sealed (secret) until the NEXT round's
/// ABA reconstructs coin-secret `rr` on demand for ABA round `rr`.
///
/// This bounds the number of ABA rounds for which we can supply an
/// unpredictable coin; beyond it (probability ~2^-PPT_COIN_RESERVE per
/// instance, negligible) the ACS falls back to the deterministic
/// genesis-style hash coin. MMR ABA terminates in O(1) expected ABA
/// rounds, so a modest reserve covers the overwhelming majority of
/// executions.
pub const PPT_COIN_RESERVE: usize = 12;

/// AVSS transport selector for the PPT random beacon.
///
/// The PPT scheme needs to deliver dealer-to-recipient confidential
/// share material once per round per dealer. Two transports satisfy
/// this requirement:
///
/// * **`Lite`** (default) — direct cleartext per-recipient unicast
///   of `AvssRecipientPayload` (still HMAC-authenticated via the
///   existing `WrapperMsg` + `sec_key_map` per-pair shared secret)
///   plus a single broadcast `AvssPublicCommitMsg` carrying the
///   public Merkle roots + degree-test coefficients. Wire complexity:
///   `O(n)` messages per dealer per round.
///
///   Trust model: relies on the underlying wire transport (TLS or
///   trusted LAN) to prevent passive eavesdroppers from reading the
///   share material between AVSS dispersal and the post-ACS
///   `MulticastRecoveredShares` broadcast (which reveals the same
///   share material in cleartext for audit purposes anyway). This
///   matches every other PPT wire message's threat model.
///
/// * **`SecMsg`** — Shoup-Smart 2024 Sec 4.3 Π_SecMsgDst transport:
///   encrypts every per-recipient payload with a Shamir-shared
///   master key + per-recipient hash-chain PRG stream, and disperses
///   both the key shares and the ciphertexts via RBC-style RelMsgDst
///   channels with full Bracha echo / vote agreement. Wire
///   complexity: `O(n^2)` messages per dealer per round.
///
///   Trust model: tolerates passive wire eavesdroppers (no TLS
///   required). Useful for paper-compliance testing and for
///   deployments where the network layer cannot be relied upon for
///   confidentiality.
///
/// Selected once at startup via the CLI `--transport=lite|secmsg`
/// flag and pushed into `Context::transport`. Every honest node in
/// a single deployment must agree on the same transport for the
/// dealer set to converge in ACS (mixed transports would still
/// converge because both wire variants are accepted on the
/// receive side, but only one set of variants is ever emitted, so
/// running mixed in one cluster is unsupported).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AvssTransport {
    /// Default; see enum-level doc.
    Lite,
    /// Shoup-Smart Sec 4.3 (paper-compliant); see enum-level doc.
    SecMsg,
}

impl AvssTransport {
    pub fn as_str(&self) -> &'static str {
        match self {
            AvssTransport::Lite => "lite",
            AvssTransport::SecMsg => "secmsg",
        }
    }
}

/// PPT random-beacon node context (pure-PPT mode: frequency φ = 1,
/// every honest node is always a dealer, no anytrust committee, no
/// legacy Binary-AA / Gather / CTRBC paths).
pub struct Context {
    // ---- Networking ----
    pub net_send: TcpReliableSender<Replica, WrapperMsg, Acknowledgement>,
    pub net_recv: mpsc::Receiver<WrapperMsg>,
    pub sync_send: TcpReliableSender<Replica, SyncMsg, Acknowledgement>,
    pub sync_recv: mpsc::Receiver<SyncMsg>,

    // ---- Identity / sizing ----
    pub num_nodes: usize,
    pub myid: usize,
    pub num_faults: usize,
    pub sec_key_map: HashMap<Replica, Vec<u8>>,

    // ---- Crypto context ----
    /// `HashState` (AES-PRF + Merkle hasher) wrapped in `Arc` so it
    /// can be cheaply shared with `tokio::task::spawn_blocking`
    /// closures on the multi-core hot path (Level 2). `HashState`
    /// itself wraps three `Aes128Enc` keyed instances which do not
    /// implement `Clone`; storing it behind `Arc` avoids any need to
    /// duplicate the cipher state per-message.
    pub hash_context: Arc<HashState>,
    pub secret_domain: BigUint,
    pub nonce_domain: BigUint,

    /// Optional `GF(2^w_p) ⊂ GF(2^w_q)` two-field profile selected by
    /// the `--field "GF2(w_p,w_q)"` CLI flag. `None` (the default)
    /// leaves the entire AVSS / degree-test stack on the legacy
    /// `BigUint` prime-field path driven by `secret_domain` /
    /// `nonce_domain` above; `Some(profile)` is wired through to
    /// downstream consumers (`batch_wssinit`, `secret_reconstruct`,
    /// `process::avss_local_packet_valid_pure`, …) in subsequent
    /// commits as each call site is migrated.
    ///
    /// This commit only carries the value; no behaviour change is
    /// observable when the flag is set.
    pub gf2_profile: Option<Gf2Profile>,

    // ---- Round bookkeeping ----
    pub curr_round: u32,
    pub max_rounds: u32,
    pub batch_size: usize,
    /// Pure-PPT mode forces frequency φ = 1.
    pub frequency: Round,
    pub round_state: HashMap<Round, CTRBCState>,

    // ---- ACS state ----
    pub acs_state: std::collections::HashMap<Round, crate::node::acs::state::AcsRound>,

    /// Globally banned dealers (across rounds). A dealer is banned
    /// the moment any honest node detects a protocol-level violation
    /// (invalid AVSS packet, equivocating ACS proposal,
    /// Merkle/commitment mismatch in the post-ACS audit). Once
    /// banned, the dealer is rejected from every future round's
    /// AVSS, ACS, and reconstruction paths.
    pub banned_dealers: HashSet<Replica>,

    /// Round → previous-round beacon bytes used to seed the new
    /// ACS common-coin derivation. Pattern is identical to
    /// `theta_per_round`: `record_beacon_output_for_coin(round, ..)`
    /// inserts under key `round + 1` so the next ACS round can call
    /// `coin_seed_for_acs_round(round + 1)` and obtain a value
    /// without any further lookup.
    ///
    /// For round 0 the ACS common coin uses the public genesis seed
    /// `PPT_GENESIS_COIN_SEED`; this map only carries entries for
    /// round >= 1, populated as the protocol completes earlier rounds.
    pub coin_per_round: HashMap<Round, Vec<u8>>,

    // ---- Shoup-Smart 2024 SecMsgDst-wrapped AVSS receiver state (commit 6) ----
    //
    // Receiver-side caches for the new Π_SecMsgDst-routed AVSS dealer
    // path. The dealer is unchanged in commit 6 (still uses the
    // legacy `AVSSSend` cleartext unicast); these fields plumb the
    // INCOMING side so commit 7 can flip the cutover atomically.
    //
    // For each (round, dealer) we track:
    //   - `avss_secmsg_state` — one `SecMsgDstState` instance lazily
    //     created on the first arriving SecMsgDst-tagged message;
    //     handles the key channel + cipher channel internally.
    //   - `avss_secmsg_public` — the broadcast `AvssPublicCommitMsg`
    //     (Merkle roots + h(x) coefficients + transcript binding);
    //     populated on `AVSSSecMsgPublicCommit` receipt.
    //   - `avss_secmsg_delivered_bytes` — the decrypted plaintext
    //     bytes after `SecMsgDstState` emits `DeliveredMessage`.
    //     `commit 7` will deserialize these into
    //     `AvssRecipientPayload`, validate Merkle proofs against
    //     `avss_secmsg_public`, run two-field degree test, store in
    //     `CTRBCState`, and trigger `AVSSReady`/`AVSSComplete`.
    //
    // In commit 6 the handlers stop at "store decrypted bytes" — no
    // AVSS-completion is signalled via this path, so the dealer's
    // legacy `AVSSSend` continues to drive the actual quorum.
    pub avss_secmsg_state: HashMap<
        (Round, Replica),
        crate::node::shoup_smart::sec_msg_dst::SecMsgDstState,
    >,
    pub avss_secmsg_public: HashMap<(Round, Replica), types::beacon::AvssPublicCommitMsg>,
    pub avss_secmsg_delivered_bytes: HashMap<(Round, Replica), Vec<u8>>,

    // ---- ACS unpredictable common coin (PPT problem-1 fix) ----
    //
    // Round R's AVSS seals `PPT_COIN_RESERVE` coin-secrets; round
    // (R+1)'s ACS reconstructs them on demand to drive its MMR-ABA
    // common coin. `coin_material[R]` holds what round (R+1) needs:
    // the agreed contributing dealer set (= round R's ACS-decided
    // set), the per-dealer Merkle roots for the sealed coin indices,
    // and THIS node's own shares of those sealed coins (for revealing).
    pub coin_material: HashMap<Round, crate::node::acs::coin::CoinMaterial>,

    // Per (acs_round, aba_round): collected, Merkle-validated coin
    // shares `dealer -> provider -> share`. Reconstruction of each
    // dealer's sealed coin-secret needs f+1 providers.
    pub coin_shares: HashMap<
        (Round, u64),
        HashMap<Replica, HashMap<Replica, BigUint>>,
    >,
    // Reconstructed coin secret `C = Σ_d c_{d}` per (acs_round, aba_round).
    pub coin_reconstructed: HashMap<(Round, u64), BigUint>,
    // (acs_round, aba_round) for which this node has already broadcast
    // its own coin-share reveal (idempotency; also enforces that we
    // release our share at most once, after entering that ABA round).
    pub coin_reveal_sent: HashSet<(Round, u64)>,
    // Reveals that arrived before `coin_material[acs_round-1]` was
    // locally available; replayed once the material is stashed.
    pub coin_reveal_pending:
        HashMap<(Round, u64), Vec<(types::beacon::BatchWSSReconMsg, Replica)>>,

    /// Selected AVSS transport for this node's PPT deployment
    /// (`Lite` default = O(n) per-recipient unicast; `SecMsg` =
    /// Shoup-Smart Sec 4.3 Π_SecMsgDst). The dealer path branches on
    /// this; the receive side accepts both wire families.
    pub transport: AvssTransport,

    // ---- Audit fire-and-forget plumbing (P0-A.1) ----
    //
    // post-ACS audit (the bulk of `process_multicast_recovered_shares`)
    // does not feed back into the round-r protocol pipeline -- it
    // only records blame and bans dealers from FUTURE rounds. Running
    // it inline on the consensus task's main loop blocks every other
    // inbound message (in particular round-r+1's AVSSSend packets)
    // for the duration of the audit + spawn_blocking await -- which
    // empirically caused PPT b=500 / b=1000 to stall after only
    // 31 / 19 seconds of an 80 s benchmark.
    //
    // The fix detaches the audit + spawn_blocking work into an
    // independent `tokio::spawn`-ed task that publishes its blame
    // events back to the main loop via the channel below. The main
    // loop drains the channel in a `tokio::select!` arm and applies
    // the blame writes (`blame_dealer`, `ban_dealer_global`,
    // `maybe_release_round`) on the consensus task's worker thread,
    // so all `Context` mutations remain serialised exactly as before.
    //
    // Result: the consensus main loop no longer awaits the audit
    // task, and round-r+1's AVSSSend / ACS messages can be processed
    // immediately while round-r's audit runs in parallel on the
    // tokio blocking pool.
    pub audit_tx: mpsc::UnboundedSender<AuditCompletion>,
    pub audit_rx: mpsc::UnboundedReceiver<AuditCompletion>,

    // ---- AVSS validation fire-and-forget (Phase D) ----
    //
    // `process_avss_send` used to await its `spawn_blocking`
    // `avss_local_packet_valid_pure` call synchronously on the
    // consensus main task. With n=16, batch=1000, each await is
    // ~25 ms of degree-test + Merkle work, and per round per node
    // we receive 16 AVSS packets. The main task therefore spent
    // up to 400 ms per round serialised on AVSS validation
    // awaits, blocking it from processing the round-(r+1)
    // BatchBeaconConstruct / ACS messages that were already
    // queued in `net_recv`.
    //
    // Phase D extends the P0-A.1 audit fire-and-forget pattern to
    // AVSS validation: `process_avss_send` now `tokio::spawn`s a
    // detached task that runs the `spawn_blocking` validation and
    // publishes the result back via `avss_validation_tx`. The
    // main loop drains the corresponding `avss_validation_rx`
    // arm in `tokio::select!` and applies the
    // `store_avss_packet` + `AVSSReady` broadcast + AVSS-
    // completion cascade on its own thread, so every `Context`
    // mutation stays single-threaded as before -- no Mutex
    // required on the hot path.
    //
    // Throughput consequence: 16 inbound AVSS validations per
    // round per node now run in PARALLEL on tokio's blocking
    // pool. End-to-end AVSS-phase wall time per round drops from
    // 16 * 25 ms = 400 ms to ~50 ms on an 8-core machine.
    pub avss_validation_tx: mpsc::UnboundedSender<AvssValidationCompletion>,
    pub avss_validation_rx: mpsc::UnboundedReceiver<AvssValidationCompletion>,

    // ---- Reconstruct ingest fire-and-forget (Phase D) ----
    //
    // Same problem as the AVSS validation channel above but for
    // `process_batch_secret_shares`, which used to await
    // `verify_batch_shares_pure` (degree-test for all
    // n_decided_dealers * batch coins in a single inbound
    // BatchBeaconConstruct packet) synchronously.
    //
    // Empirically (n=16, batch=1000): each inbound packet's
    // verify_batch_shares_pure await took ~120 ms, n inbound
    // packets per round per node => ~2 s of sequential main-loop
    // time on reconstruct alone. That dominated the round budget
    // (see log: `ACS-DECIDE -> coin-0 BEACON-OUT` ~= 2.2 s).
    //
    // Phase D detaches verify_batch_shares_pure the same way and
    // sends a `ReconCompletion` back via the channel below; the
    // main loop applies accepted shares + blame events on its
    // own thread and triggers `maybe_recover_ready_coins`.
    //
    // 16 inbound packets now validated in parallel on the
    // blocking pool. Reconstruct-phase wall time drops from
    // ~2 s to ~250 ms on an 8-core machine.
    pub recon_tx: mpsc::UnboundedSender<ReconCompletion>,
    pub recon_rx: mpsc::UnboundedReceiver<ReconCompletion>,

    // ---- Diagnostics / lifecycle ----
    pub num_messages: u32,
    pub bench: HashMap<String, u128>,
    pub cancel_handlers: HashMap<Round, Vec<CancelHandler<Acknowledgement>>>,
    exit_rx: oneshot::Receiver<()>,
}

/// Result of one detached `process_multicast_recovered_shares` audit
/// run. The detached task computes `blame_events` from the spawn_blocking
/// audit and sends this struct back to the main loop, which then
/// performs the blame / ban writes on `Context` (single-threaded).
#[derive(Debug)]
pub struct AuditCompletion {
    pub round: Round,
    pub blame_events: Vec<(Replica, crate::node::ctrbc::state::BlameReason)>,
}

/// Result of one detached `avss_local_packet_valid_pure` run, used
/// by the AVSS validation fire-and-forget path. The detached task
/// runs the CPU-heavy validation on the blocking pool and sends
/// this struct back to the main loop, which applies
/// `store_avss_packet` + `AVSSReady` broadcast + cascade on its
/// own thread.
#[derive(Debug)]
pub struct AvssValidationCompletion {
    pub round: Round,
    pub dealer: Replica,
    pub transcript_root: crypto::hash::Hash,
    /// The validated BeaconMsg moved out of the spawn_blocking
    /// closure. Stored back into CTRBCState verbatim once
    /// validation succeeds.
    pub beacon_msg: types::beacon::BeaconMsg,
    /// `Ok(())` on successful validation; `Err(static_reason)` on
    /// any Byzantine-detectable failure (transcript mismatch,
    /// Merkle invalid, degree-test failed, share/f_large mismatch,
    /// mp.root/root_vec mismatch). The main loop bans the dealer
    /// on `Err(_)`.
    pub result: Result<(), &'static str>,
}

/// Result of one detached `verify_batch_shares_pure` run, used by
/// the BatchBeaconConstruct fire-and-forget reconstruct ingest
/// path. The detached task runs the per-coin degree-test for all
/// (dealer, coin) tuples in one inbound BatchBeaconConstruct
/// packet, on the blocking pool, and sends this struct back to the
/// main loop, which applies `add_secret_share` + blame writes on
/// its own thread and triggers `maybe_recover_ready_coins`.
#[derive(Debug)]
pub struct ReconCompletion {
    pub round: Round,
    pub share_sender: Replica,
    /// Whether the share_sender is itself in the ACS-decided set.
    /// Mirrors the `use_for_batch` predicate that
    /// `process_batch_secret_shares` previously computed inline.
    /// Only `Accepted` outcomes whose `share_sender` is
    /// `use_for_batch == true` are persisted via
    /// `add_secret_share`.
    pub use_for_batch: bool,
    pub outcomes: Vec<crate::node::batch_wss::secret_reconstruct::CoinVerifyOutcome>,
}

impl Context {
    pub fn spawn(
        config: Node,
        _sleep: u128,
        batch: usize,
        frequency: Round,
        transport: AvssTransport,
        gf2_profile: Option<Gf2Profile>,
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

        let (tx_net_to_consensus, rx_net_to_consensus) =
            mpsc::channel::<WrapperMsg>(PPT_INBOUND_CHANNEL_CAPACITY);
        TcpReceiver::<Acknowledgement, WrapperMsg, _>::spawn(
            my_address,
            Handler::new(tx_net_to_consensus),
        );

        let syncer_listen_port = config.client_port;
        let syncer_l_address = to_socket_address("0.0.0.0", syncer_listen_port);

        let (tx_net_to_client, rx_net_from_client) =
            mpsc::channel::<SyncMsg>(PPT_INBOUND_CHANNEL_CAPACITY);
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

            // Audit fire-and-forget channel (see field comment above).
            let (audit_tx, audit_rx) = mpsc::unbounded_channel::<AuditCompletion>();
            // AVSS validation + reconstruct fire-and-forget channels
            // (Phase D; see field comments above).
            let (avss_validation_tx, avss_validation_rx) =
                mpsc::unbounded_channel::<AvssValidationCompletion>();
            let (recon_tx, recon_rx) = mpsc::unbounded_channel::<ReconCompletion>();

            let mut c = Context {
                net_send: consensus_net,
                net_recv: rx_net_to_consensus,
                sync_send: sync_net,
                sync_recv: rx_net_from_client,

                num_nodes: config.num_nodes,
                sec_key_map: HashMap::default(),
                myid: config.id,
                num_faults: config.num_faults,

                hash_context: Arc::new(hashstate),
                secret_domain: prime.clone(),
                nonce_domain: nonce_prime.clone(),
                gf2_profile,

                curr_round: 0,
                max_rounds: 20000,
                batch_size: batch,
                frequency: pure_ppt_frequency,
                round_state: HashMap::default(),

                acs_state: std::collections::HashMap::new(),
                banned_dealers: HashSet::new(),
                audit_tx,
                audit_rx,
                avss_validation_tx,
                avss_validation_rx,
                recon_tx,
                recon_rx,
                coin_per_round: HashMap::default(),

                avss_secmsg_state: HashMap::default(),
                avss_secmsg_public: HashMap::default(),
                avss_secmsg_delivered_bytes: HashMap::default(),

                coin_material: HashMap::default(),
                coin_shares: HashMap::default(),
                coin_reconstructed: HashMap::default(),
                coin_reveal_sent: HashSet::new(),
                coin_reveal_pending: HashMap::default(),

                transport,

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
            match c.gf2_profile {
                Some(p) => log::error!(
                    "[PPT][FIELD] node {} two-field profile = {} (BigUint path remains active; \
                     migration commits will switch consumers progressively)",
                    c.myid,
                    p
                ),
                None => log::error!(
                    "[PPT][FIELD] node {} two-field profile = BigUint (default; pass \
                     --field 'GF2(w_p,w_q)' to enable the binary-extension-field profile)",
                    c.myid
                ),
            }

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

    /// Fiat-Shamir degree-test challenge θ for a dealer's AVSS
    /// packet (PPT problem-3 fix). θ is derived from the dealer's
    /// OWN commitment (`root_vec`, the per-coin Merkle roots that bind
    /// every recipient's f-share, g-share and f_large via
    /// `avss_commit_leaf`), so the dealer must commit f and g BEFORE θ
    /// is determined. A Byzantine dealer can therefore no longer pick
    /// the mask `g` to cancel a high-degree `f` (it would need a hash
    /// collision), making the two-field degree test sound with error
    /// 1/|q|. Replaces the old θ = H(previous PUBLIC beacon), which
    /// the dealer could predict and bypass.
    ///
    /// θ is per-(round, dealer); every honest verifier recomputes the
    /// identical value from the same committed `root_vec`, so the
    /// degree test is checked against the same challenge everywhere.
    pub(crate) fn theta_from_commitment(
        round: Round,
        dealer: Replica,
        root_vec: &[Hash],
        large_field: &BigUint,
    ) -> BigUint {
        let mut buf: Vec<u8> = b"PPT_BEACON_FS_THETA_v1::".to_vec();
        buf.extend_from_slice(&round.to_be_bytes());
        buf.extend_from_slice(&(dealer as u64).to_be_bytes());
        buf.extend_from_slice(&(root_vec.len() as u64).to_be_bytes());
        for r in root_vec {
            buf.extend_from_slice(r);
        }
        Self::theta_from_bytes(buf.as_slice(), large_field)
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
    ///
    /// **Hot-path optimisation (P0-A)**: the wire bytes of `protmsg`
    /// are byte-identical for every recipient -- only the per-
    /// recipient HMAC differs because each peer has its own pre-
    /// shared symmetric key. The previous implementation called
    /// `WrapperMsg::new(...)` once per recipient, which internally
    /// re-ran `bincode::serialize(&protmsg)` n-1 times even though
    /// the output was the same every time. With the new ACS
    /// pipeline emitting ~80 broadcasts per round per node (RBC
    /// SEND/ECHO/READY × n proposers + ABA BVAL/AUX × n instances),
    /// the redundant serialisation became a measurable share of
    /// the consensus task's CPU budget.
    ///
    /// The new implementation:
    ///   1. serialises `protmsg` exactly once into a `Vec<u8>`,
    ///   2. for every recipient computes only the HMAC over those
    ///      shared bytes using that recipient's secret key, and
    ///   3. constructs the `WrapperMsg` with the (cheap) `protmsg`
    ///      clone for the wire payload + the per-recipient mac.
    ///
    /// Wire format is unchanged (no `WrapperMsg` field rename), so
    /// this is a pure implementation-side optimisation. ACS three-
    /// property safety is unaffected.
    ///
    /// We also avoid the previous `self.sec_key_map.clone()` per
    /// broadcast by collecting the recipient list up-front into a
    /// small `Vec<(Replica, Vec<u8>)>`, releasing the immutable
    /// borrow before any `&mut self` operation.
    pub async fn broadcast(&mut self, protmsg: CoinMsg, round: Round) {
        // (1) serialise once -- this is what `WrapperMsg::new`
        //     internally did n-1 times before.
        let bytes = bincode::serialize(&protmsg)
            .expect("Failed to serialize protmsg for broadcast");

        let myid = self.myid;

        // (2) collect (replica, mac) for every recipient using the
        //     shared `bytes`. We snapshot the keys first so we can
        //     drop the immutable borrow on `self.sec_key_map` before
        //     touching `self.net_send` and `self.cancel_handlers`.
        //     This loop is pure CPU (HMAC-SHA256) and runs in tens
        //     of microseconds per recipient.
        let mut wrappers: Vec<(Replica, WrapperMsg)> =
            Vec::with_capacity(self.sec_key_map.len());
        for (replica, sec_key) in self.sec_key_map.iter() {
            if *replica == myid {
                continue;
            }
            let mac = crypto::hash::do_mac(bytes.as_slice(), sec_key.as_slice());
            // The wire format expects an owned `protmsg`; the clone
            // here is the only remaining per-recipient cost.
            let wrapper = WrapperMsg {
                protmsg: protmsg.clone(),
                sender: myid,
                mac,
                round,
            };
            wrappers.push((*replica, wrapper));
        }

        // (3) push the wrappers to per-recipient channels. Each call
        //     is sub-microsecond (TcpReliableSender::send only does
        //     a synchronous channel push -- the actual TCP I/O runs
        //     in a separately-spawned per-connection task), so there
        //     is no benefit to wrapping these in `join_all`.
        for (replica, wrapper) in wrappers {
            let cancel_handler: CancelHandler<Acknowledgement> =
                self.net_send.send(replica, wrapper).await;
            self.add_cancel_handler(cancel_handler);
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
                    // Yield after every inbound message so a single
                    // expensive `process_msg` (e.g. ingest of a
                    // batch_size=100 BatchBeaconConstruct + cascade
                    // of n broadcasts) doesn't starve the rest of
                    // the tokio worker. Without this, head-of-line
                    // blocking under high round-rate (batch=20 case)
                    // would let the inbound queue grow until the
                    // protocol stalled.
                    tokio::task::yield_now().await;
                }
                Some(audit_completion) = self.audit_rx.recv() => {
                    // Audit fire-and-forget result (P0-A.1):
                    //
                    // A previously-spawned detached task finished its
                    // post-ACS audit (the spawn_blocking
                    // `audit_post_complaint_pure` call inside
                    // `process_multicast_recovered_shares`) and produced
                    // `blame_events`. Apply them here on the consensus
                    // task's worker thread so all `Context` mutations
                    // (banned_dealers, round_state) remain
                    // single-threaded-serialised, with no need for
                    // Mutex-style locking on the hot path.
                    self.finalize_audit_completion(audit_completion).await;
                }
                Some(avss_completion) = self.avss_validation_rx.recv() => {
                    // Phase D fire-and-forget for AVSS validation:
                    //
                    // A detached task running on tokio's blocking
                    // pool finished validating one inbound
                    // BeaconMsg via `avss_local_packet_valid_pure`.
                    // Apply store_avss_packet + AVSSReady
                    // broadcast + AVSS-completion cascade here, on
                    // the consensus task's worker thread, so all
                    // Context mutations (round_state, banned_dealers)
                    // stay single-threaded as before.
                    self.finalize_avss_validation(avss_completion).await;
                }
                Some(recon_completion) = self.recon_rx.recv() => {
                    // Phase D fire-and-forget for BatchBeaconConstruct
                    // ingest:
                    //
                    // A detached task running on tokio's blocking
                    // pool finished the degree-test for one inbound
                    // BatchBeaconConstruct packet via
                    // `verify_batch_shares_pure`. Apply add_secret_share
                    // + blame writes here, then trigger
                    // `maybe_recover_ready_coins`.
                    self.finalize_recon_completion(recon_completion).await;
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
