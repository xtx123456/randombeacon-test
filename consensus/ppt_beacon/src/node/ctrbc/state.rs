//! Per-round PPT state.
//!
//! After the P0 protocol refactor and the P1 dead-code purge, this
//! struct only carries fields that the live PPT path actually reads:
//!
//! - AVSS bookkeeping (transcript-root votes, completed dealers,
//!   stored AVSS packets, two-field side data);
//! - reconstruction state (per-coin shares, recovered secrets,
//!   batch extractor cached for the immutable ACS-decided set);
//! - post-ACS audit evidence (commitment vectors, blame log,
//!   recovered-share multicast snapshots);
//! - emit / progress flags consumed by the syncer-facing path.
//!
//! All hashrand-era CTRBC / Gather / Approximate-Agreement state has
//! been removed. The struct name `CTRBCState` is kept for backward
//! compatibility with the historical layout but it is no longer
//! related to Cachin-Tessaro RBC.

use std::collections::{HashMap, HashSet};

use crypto::hash::Hash;
use num_bigint::BigUint;

use types::{
    beacon::{
        BatchWSSMsg, BatchWSSReconMsg, BeaconMsg, MulticastRecoveredSharesMsg, Round, Val,
    },
    Replica,
};

use crate::node::shamir::two_field::BatchExtractor;

/// Post-ACS accountability evidence: who is being blamed, in which
/// round, and why. The driver in `Context::ban_dealer_global` is the
/// thing that actually banishes the dealer from future rounds; this
/// struct just records the evidence.
#[derive(Debug, Clone)]
pub struct BlameEvidence {
    pub dealer: Replica,
    pub round: Round,
    pub reason: BlameReason,
}

#[derive(Debug, Clone)]
pub enum BlameReason {
    /// Share+nonce hash did not match the dealer's committed Merkle root.
    CommitmentMismatch {
        coin_num: usize,
        expected_root: Hash,
        got_item: Hash,
    },
    /// Merkle proof root did not match the committed root.
    MerkleRootMismatch {
        coin_num: usize,
        expected_root: Hash,
        got_root: Hash,
    },
    /// A dealer in the ACS-decided set has no degree-test coefficients
    /// stored locally for some coin — only possible if the dealer never
    /// sent us a valid AVSS packet.
    MissingDegreeTestCoeffs { coin_num: usize },
    /// A dealer in the ACS-decided set has no commitment vector stored
    /// locally — only possible if the dealer never sent us a valid AVSS
    /// packet.
    MissingCommitmentVector,
}

#[derive(Debug, Clone)]
pub struct CTRBCState {
    // ---- AVSS book ----
    /// Per-dealer raw `BatchWSSMsg` (secrets / nonces / Merkle proofs).
    pub node_secrets: HashMap<Replica, BatchWSSMsg, nohash_hasher::BuildNoHashHasher<Replica>>,

    /// Per-dealer commitment vector (the publicly-broadcast Merkle
    /// roots, one per coin in the batch).
    pub comm_vectors: HashMap<Replica, Vec<Hash>, nohash_hasher::BuildNoHashHasher<Replica>>,

    /// Public hash transcript commitment per dealer's AVSS instance.
    pub avss_transcript_roots:
        HashMap<Replica, Hash, nohash_hasher::BuildNoHashHasher<Replica>>,

    /// Dealers for which this node has locally validated the AVSS packet.
    pub avss_local_valid: HashSet<Replica, nohash_hasher::BuildNoHashHasher<Replica>>,

    /// Per-dealer AVSSReady votes: `dealer -> sender -> claimed root`.
    pub avss_ready_votes:
        HashMap<Replica, HashMap<Replica, Hash>, nohash_hasher::BuildNoHashHasher<Replica>>,

    /// Per-dealer AVSSComplete votes: `dealer -> sender -> claimed root`.
    pub avss_complete_votes:
        HashMap<Replica, HashMap<Replica, Hash>, nohash_hasher::BuildNoHashHasher<Replica>>,

    /// Dealers we have already broadcast `AVSSComplete` for.
    pub avss_complete_sent: HashSet<Replica, nohash_hasher::BuildNoHashHasher<Replica>>,

    /// Dealers whose AVSS instance has completed locally and can be
    /// fed into ACS (the ACS driver also re-checks `Context::banned_dealers`).
    pub avss_completed_dealers: HashSet<Replica, nohash_hasher::BuildNoHashHasher<Replica>>,

    // ---- Two-field per-dealer side data ----
    /// `degree_test_coeffs[dealer][coin] = h(x) coefficients`.
    pub degree_test_coeffs:
        HashMap<Replica, Vec<Vec<Val>>, nohash_hasher::BuildNoHashHasher<Replica>>,
    /// `mask_shares[dealer][coin] = g(i) mod q` (one per coin).
    pub mask_shares: HashMap<Replica, Vec<Val>, nohash_hasher::BuildNoHashHasher<Replica>>,
    /// `f_large_shares[dealer][coin] = f(i) mod q`.
    pub f_large_shares: HashMap<Replica, Vec<Val>, nohash_hasher::BuildNoHashHasher<Replica>>,

    // ---- Reconstruction ----
    /// `coin -> dealer -> share_provider -> share_value`.
    pub secret_shares: HashMap<
        usize,
        HashMap<Replica, HashMap<Replica, BigUint>>,
        nohash_hasher::BuildNoHashHasher<Replica>,
    >,
    /// Recovered f(0) per dealer, keyed by coin index.
    pub reconstructed_secrets: HashMap<
        Replica,
        HashMap<Replica, BigUint, nohash_hasher::BuildNoHashHasher<Replica>>,
        nohash_hasher::BuildNoHashHasher<Replica>,
    >,
    /// Coins for which we have already emitted the beacon output to
    /// the syncer; used by the `is_last_coin` short-circuit.
    pub recon_secrets: HashSet<usize>,

    // ---- ACS-bound reconstruction ----
    /// Lagrange-coefficient cache for the immutable ACS-decided
    /// evaluation points. Populated by `finalize_acs_round`.
    pub batch_extractor: Option<BatchExtractor>,
    /// Immutable ACS decision used as the reconstruction basis.
    pub acs_decided_set: Option<Vec<Replica>>,
    /// `BeaconConstruct` packets that arrived before ACS finalised;
    /// replayed once `finalize_acs_round` runs.
    pub pre_acs_beacon_constructs: Vec<(BatchWSSReconMsg, Replica, usize)>,

    // ---- Post-ACS audit / accountability ----
    pub post_complaint_packets: HashMap<
        Replica,
        MulticastRecoveredSharesMsg,
        nohash_hasher::BuildNoHashHasher<Replica>,
    >,
    pub recovered_shares_multicast_sent: bool,
    pub batch_reconstruction_complete: bool,
    pub post_complaint_complete: bool,
    pub blame_log: Vec<BlameEvidence>,

    /// Coins already batch-recovered.
    pub recovered_coins: HashSet<usize, nohash_hasher::BuildNoHashHasher<usize>>,
    /// Coins already exposed in our post-ACS multicast snapshot.
    pub multicast_disclosed_coins: HashSet<usize, nohash_hasher::BuildNoHashHasher<usize>>,
    /// Coins whose beacon output has already been emitted upstream.
    pub emitted_beacon_coins: HashSet<usize, nohash_hasher::BuildNoHashHasher<usize>>,
    /// Beacon outputs computed by batch recovery, held until the
    /// post-complaint audit is allowed to release them.
    pub pending_beacon_outputs:
        HashMap<usize, Vec<u8>, nohash_hasher::BuildNoHashHasher<usize>>,

    // ---- Round bootstrap flags ----
    /// Pure-PPT mode dealer-launch idempotency flag.
    pub ppt_round_started: bool,
    /// Set once the syncer-side last-coin event has fired.
    pub ppt_round_finished: bool,

    // ---- Misc ----
    pub secret_domain: BigUint,
    /// Set after `_clear`; used by the recon ingest path to short-circuit.
    pub cleared: bool,
}

impl CTRBCState {
    pub fn new(sec_domain: BigUint, num_nodes: usize) -> CTRBCState {
        let _ = num_nodes; // signature compatibility with older call sites
        CTRBCState {
            node_secrets: HashMap::default(),
            comm_vectors: HashMap::default(),

            avss_transcript_roots: HashMap::default(),
            avss_local_valid: HashSet::default(),
            avss_ready_votes: HashMap::default(),
            avss_complete_votes: HashMap::default(),
            avss_complete_sent: HashSet::default(),
            avss_completed_dealers: HashSet::default(),

            degree_test_coeffs: HashMap::default(),
            mask_shares: HashMap::default(),
            f_large_shares: HashMap::default(),

            secret_shares: HashMap::default(),
            reconstructed_secrets: HashMap::default(),
            recon_secrets: HashSet::default(),

            batch_extractor: None,
            acs_decided_set: None,
            pre_acs_beacon_constructs: Vec::new(),

            post_complaint_packets: HashMap::default(),
            recovered_shares_multicast_sent: false,
            batch_reconstruction_complete: false,
            post_complaint_complete: false,
            blame_log: Vec::new(),

            recovered_coins: HashSet::default(),
            multicast_disclosed_coins: HashSet::default(),
            emitted_beacon_coins: HashSet::default(),
            pending_beacon_outputs: HashMap::default(),

            ppt_round_started: false,
            ppt_round_finished: false,

            secret_domain: sec_domain,
            cleared: false,
        }
    }

    pub fn store_avss_packet(
        &mut self,
        dealer: Replica,
        beacon_msg: BeaconMsg,
        transcript_root: Hash,
    ) {
        self.avss_transcript_roots.insert(dealer, transcript_root);

        if let Some(ref dtc) = beacon_msg.degree_test_coeffs {
            self.degree_test_coeffs.insert(dealer, dtc.clone());
        }
        if let Some(ref mask) = beacon_msg.mask_shares {
            self.mask_shares.insert(dealer, mask.clone());
        }
        if let Some(ref f_large) = beacon_msg.f_large_shares {
            self.f_large_shares.insert(dealer, f_large.clone());
        }
        if let Some(ref batch_wssmsg) = beacon_msg.wss {
            self.node_secrets.insert(dealer, batch_wssmsg.clone());
        }
        if let Some(ref root_vec) = beacon_msg.root_vec {
            self.comm_vectors.insert(dealer, root_vec.clone());
        }
    }

    pub fn add_avss_ready_vote(&mut self, dealer: Replica, sender: Replica, transcript_root: Hash) {
        self.avss_ready_votes
            .entry(dealer)
            .or_default()
            .insert(sender, transcript_root);
    }

    pub fn add_avss_complete_vote(
        &mut self,
        dealer: Replica,
        sender: Replica,
        transcript_root: Hash,
    ) {
        self.avss_complete_votes
            .entry(dealer)
            .or_default()
            .insert(sender, transcript_root);
    }

    pub fn matching_avss_ready_count(&self, dealer: Replica) -> usize {
        let transcript_root = match self.avss_transcript_roots.get(&dealer) {
            Some(root) => root,
            None => return 0,
        };
        match self.avss_ready_votes.get(&dealer) {
            Some(votes) => votes
                .values()
                .filter(|root| **root == *transcript_root)
                .count(),
            None => 0,
        }
    }

    pub fn matching_avss_complete_count(&self, dealer: Replica) -> usize {
        let transcript_root = match self.avss_transcript_roots.get(&dealer) {
            Some(root) => root,
            None => return 0,
        };
        match self.avss_complete_votes.get(&dealer) {
            Some(votes) => votes
                .values()
                .filter(|root| **root == *transcript_root)
                .count(),
            None => 0,
        }
    }

    pub fn add_secret_share(
        &mut self,
        coin_number: usize,
        secret_id: usize,
        share_provider: usize,
        share: Val,
    ) {
        let share_bg = BigUint::from_bytes_be(&share);
        self.secret_shares
            .entry(coin_number)
            .or_default()
            .entry(secret_id)
            .or_default()
            .insert(share_provider, share_bg);
    }

    /// Pure-PPT stub kept so `Context` callers don't have to special-case
    /// the absence. Beacon aggregation no longer depends on legacy
    /// approximate-agreement weights.
    pub async fn sync_secret_maps(&mut self) {
        // intentionally empty
    }

    /// Record a dealer in the per-round blame log. The actual ban
    /// (cross-round, persistent) is performed by
    /// `Context::ban_dealer_global`; this struct just keeps an audit
    /// trail per round.
    pub fn blame_dealer(&mut self, dealer: Replica, round: Round, reason: BlameReason) {
        if !self
            .blame_log
            .iter()
            .any(|ev| ev.dealer == dealer && ev.round == round)
        {
            log::error!(
                "[POST-BLAME] Dealer {} flagged in round {}: {:?}",
                dealer,
                round,
                reason
            );
            self.blame_log.push(BlameEvidence {
                dealer,
                round,
                reason,
            });
        }
    }

    /// Build the recovered-shares multicast packet for one coin
    /// (post-ACS audit). Only ACS-decided dealers are included.
    pub fn secret_shares(&self, coin_number: usize) -> BatchWSSReconMsg {
        let mut shares_vector = Vec::new();
        let mut replicas = Vec::new();
        let mut nonces = Vec::new();
        let mut merkle_proofs = Vec::new();
        let mut mask_shares = Vec::new();
        let mut f_large_shares = Vec::new();

        let decided = self.acs_decided_set.clone().unwrap_or_default();
        for rep in decided.into_iter() {
            let batch_wss = match self.node_secrets.get(&rep) {
                Some(batch_wss) => batch_wss,
                None => continue,
            };
            let secret = match batch_wss.secrets.get(coin_number) {
                Some(secret) => secret,
                None => continue,
            };
            let nonce = match batch_wss.nonces.get(coin_number) {
                Some(nonce) => nonce,
                None => continue,
            };
            let merkle_proof = match batch_wss.mps.get(coin_number) {
                Some(merkle_proof) => merkle_proof,
                None => continue,
            };
            let mask = match self.mask_shares.get(&rep).and_then(|v| v.get(coin_number)) {
                Some(mask) => mask,
                None => continue,
            };
            let f_large = match self
                .f_large_shares
                .get(&rep)
                .and_then(|v| v.get(coin_number))
            {
                Some(f_large) => f_large,
                None => continue,
            };

            shares_vector.push(*secret);
            nonces.push(*nonce);
            merkle_proofs.push(merkle_proof.clone());
            mask_shares.push(*mask);
            f_large_shares.push(*f_large);
            replicas.push(rep);
        }
        BatchWSSReconMsg {
            origin: 0,
            secrets: shares_vector,
            nonces,
            origins: replicas,
            mps: merkle_proofs,
            mask_shares,
            f_large_shares,
            empty: false,
        }
    }

    /// Pure-PPT beacon extraction: once every ACS-decided dealer has
    /// been reconstructed for `coin_number`, sum their secrets modulo
    /// the secret domain to derive the beacon value.
    ///
    /// Returns `None` if reconstruction is not yet complete for the
    /// coin or if the ACS-decided set has not been published.
    pub async fn coin_check(
        &mut self,
        round: Round,
        coin_number: usize,
        _num_nodes: usize,
    ) -> Option<Vec<u8>> {
        let decided = match self.acs_decided_set.clone() {
            Some(v) if !v.is_empty() => v,
            _ => {
                log::debug!(
                    "[PPT][COIN-CHECK] round {} coin {} skipped: ACS decided set not ready",
                    round,
                    coin_number
                );
                return None;
            }
        };

        let recon_map = match self.reconstructed_secrets.get(&coin_number) {
            Some(m) => m,
            None => {
                log::debug!(
                    "[PPT][COIN-CHECK] round {} coin {} skipped: no reconstructed secrets yet",
                    round,
                    coin_number
                );
                return None;
            }
        };

        for dealer in decided.iter().copied() {
            if !recon_map.contains_key(&dealer) {
                log::debug!(
                    "[PPT][COIN-CHECK] round {} coin {} waiting for reconstructed secret from decided dealer {}",
                    round,
                    coin_number,
                    dealer
                );
                return None;
            }
        }

        let mut sum_vars = BigUint::from(0u32);
        let mut decided_sorted = decided.clone();
        decided_sorted.sort_unstable();

        for dealer in decided_sorted.iter().copied() {
            let sec = recon_map.get(&dealer).unwrap();
            log::info!(
                "[PPT][COIN-CHECK] round {} coin {} including dealer {} reconstructed secret {}",
                round,
                coin_number,
                dealer,
                sec
            );
            sum_vars += sec.clone();
        }

        let rand_fin = sum_vars % self.secret_domain.clone();

        log::info!(
            "[PPT][COIN-CHECK] round {} coin {} pure-PPT beacon value computed (mod p)",
            round,
            coin_number
        );

        // Mark and clean up this coin's transient recovery state.
        self.recon_secrets.insert(coin_number);
        self.secret_shares.remove(&coin_number);
        self.reconstructed_secrets.remove(&coin_number);

        Some(BigUint::to_bytes_be(&rand_fin))
    }

    /// Wipe transient state when the round is fully finished (every
    /// coin emitted, post-ACS audit complete). Bookkeeping needed for
    /// the long-running `Context::banned_dealers` set is intentionally
    /// left untouched — it lives in `Context`, not here.
    pub fn clear(&mut self) {
        self.node_secrets.clear();
        self.comm_vectors.clear();

        self.avss_transcript_roots.clear();
        self.avss_local_valid.clear();
        self.avss_ready_votes.clear();
        self.avss_complete_votes.clear();
        self.avss_complete_sent.clear();
        self.avss_completed_dealers.clear();

        self.degree_test_coeffs.clear();
        self.mask_shares.clear();
        self.f_large_shares.clear();

        self.secret_shares.clear();
        self.reconstructed_secrets.clear();
        self.recon_secrets.clear();

        self.batch_extractor = None;
        self.acs_decided_set = None;
        self.pre_acs_beacon_constructs.clear();

        self.post_complaint_packets.clear();
        self.recovered_shares_multicast_sent = false;
        self.batch_reconstruction_complete = false;
        self.post_complaint_complete = false;
        self.blame_log.clear();

        self.recovered_coins.clear();
        self.multicast_disclosed_coins.clear();
        self.emitted_beacon_coins.clear();
        self.pending_beacon_outputs.clear();

        self.ppt_round_started = false;
        self.ppt_round_finished = false;

        self.cleared = true;
    }
}
