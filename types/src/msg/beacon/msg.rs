use crypto::{hash::{Hash, do_mac, do_hash}, aes_hash::{Proof, HashState, HASH_SIZE}};
use serde::{Serialize, Deserialize};

use crate::{WireReady, Round};

use super::{Replica};

pub type Val = [u8; HASH_SIZE];

/// AVSS Merkle-commitment leaf for one (coin, recipient) slot.
///
/// Binds ALL of the recipient's confidential per-coin material —
/// the small-field secret share `f(i) mod p`, the mask share
/// `g(i) mod q`, the large-field share `f(i) mod q`, and the
/// per-share nonce — into a single committed leaf. Previously only
/// `(f_share, nonce)` was committed, leaving the mask `g` free; a
/// Byzantine dealer could then pick `g(i)` AFTER learning the
/// degree-test challenge and pass the test with an arbitrary-degree
/// `f`. Committing `g` (and `f_large`) here is what makes the
/// Fiat-Shamir degree-test challenge `θ = H(round‖dealer‖root_vec)`
/// sound: the dealer must commit `f` and `g` before `θ` is
/// determined.
pub fn avss_commit_leaf(f_share: &Val, g_share: &Val, f_large: &Val, nonce: &Val) -> Hash {
    let mut buf = Vec::with_capacity(4 * HASH_SIZE);
    buf.extend_from_slice(f_share);
    buf.extend_from_slice(g_share);
    buf.extend_from_slice(f_large);
    buf.extend_from_slice(nonce);
    do_hash(buf.as_slice())
}

/// GF(2^w) variant of `avss_commit_leaf` for the binary-extension
/// two-field profile.
///
/// In GF(2^w), the small-field share `f(i) ∈ GF(2^w_p)` lifts into
/// the large field `GF(2^w_q)` as the canonical "low coordinate"
/// inclusion — i.e. `f_large = f_share` byte-for-byte after the
/// subfield embedding. Hashing `f_large` separately is therefore
/// redundant: it would bind the same 32 bytes twice. This 3-field
/// variant drops `f_large` and binds only `(f_share, g_share,
/// nonce)`, saving 32 bytes of hash input per leaf AND 32 bytes per
/// (recipient, coin) on the wire (since `f_large` no longer needs
/// to be shipped at all in GF(2^w) mode).
///
/// Wire-side: BeaconMsg / AvssRecipientPayload / BatchWSSReconMsg
/// carry `f_large_shares: Option<Vec<Val>>`. `Some(_)` selects the
/// legacy 4-field leaf (`avss_commit_leaf`); `None` selects this
/// 3-field leaf. Dealers and verifiers must agree on the profile
/// (single-deployment configuration — same cross-mode safety story
/// as `--transport`).
pub fn avss_commit_leaf_gf2(f_share: &Val, g_share: &Val, nonce: &Val) -> Hash {
    let mut buf = Vec::with_capacity(3 * HASH_SIZE);
    buf.extend_from_slice(f_share);
    buf.extend_from_slice(g_share);
    buf.extend_from_slice(nonce);
    do_hash(buf.as_slice())
}

/// Dispatch helper that selects the right leaf variant based on
/// whether `f_large` is `Some` (legacy BigUint / 4-field) or `None`
/// (GF(2^w) / 3-field). Used at every site that previously called
/// `avss_commit_leaf` directly.
#[inline]
pub fn avss_commit_leaf_auto(
    f_share: &Val,
    g_share: &Val,
    f_large: Option<&Val>,
    nonce: &Val,
) -> Hash {
    match f_large {
        Some(fl) => avss_commit_leaf(f_share, g_share, fl, nonce),
        None => avss_commit_leaf_gf2(f_share, g_share, nonce),
    }
}

#[derive(Debug,Serialize,Deserialize,Clone)]
pub struct BeaconMsg{
    pub origin: Replica,
    pub round:Round,
    pub wss:Option<BatchWSSMsg>,
    pub root_vec:Option<Vec<Hash>>,
    // Each BeaconMsg can consist AppxCon messages from multiple rounds.
    pub appx_con: Option<Vec<(Round,Vec<(Replica,Val)>)>>,
    /// Phase 4B (Two-Field): Degree test polynomial h(x) = g(x) - θ·f(x) coefficients.
    #[serde(default)]
    pub degree_test_coeffs: Option<Vec<Vec<Val>>>,
    /// Phase 4B (Two-Field): Mask shares g(i) for this recipient node.
    #[serde(default)]
    pub mask_shares: Option<Vec<Val>>,
    /// Phase 4B (Two-Field): f(i) evaluated in the large field for degree testing.
    #[serde(default)]
    pub f_large_shares: Option<Vec<Val>>,
}

impl BeaconMsg {
    pub fn new(origin:Replica,round:Round,wss_msg:BatchWSSMsg,root_vec:Vec<Hash>,appx_con: Vec<(Round,Vec<(Replica,Val)>)>)->BeaconMsg{
        BeaconMsg {
            origin,
            round,
            wss: Some(wss_msg),
            root_vec: Some(root_vec),
            appx_con: Some(appx_con),
            degree_test_coeffs: None,
            mask_shares: None,
            f_large_shares: None,
        }
    }

    /// Phase 4B (Two-Field): Create a BeaconMsg with full two-field data.
    ///
    /// `f_large_shares` is `Some(...)` in the BigUint two-field path
    /// (legacy default) and `None` in the GF(2^w) two-field path
    /// (commit 7 of the migration): under the subfield embedding
    /// `f_large == secrets` byte-for-byte, so the redundant channel
    /// is dropped on the wire and reconstructed locally by the
    /// receiver.
    pub fn new_two_field(
        origin:Replica,
        round:Round,
        wss_msg:BatchWSSMsg,
        root_vec:Vec<Hash>,
        appx_con: Vec<(Round,Vec<(Replica,Val)>)>,
        degree_test_coeffs: Vec<Vec<Val>>,
        mask_shares: Vec<Val>,
        f_large_shares: Option<Vec<Val>>,
    )->BeaconMsg{
        BeaconMsg {
            origin,
            round,
            wss: Some(wss_msg),
            root_vec: Some(root_vec),
            appx_con: Some(appx_con),
            degree_test_coeffs: Some(degree_test_coeffs),
            mask_shares: Some(mask_shares),
            f_large_shares,
        }
    }

    pub fn new_with_appx(origin:Replica,round:Round,appx_con: Vec<(Round,Vec<(Replica,Val)>)>)->BeaconMsg{
        BeaconMsg {
            origin,
            round,
            wss: None,
            root_vec: None,
            appx_con: Some(appx_con),
            degree_test_coeffs: None,
            mask_shares: None,
            f_large_shares: None,
        }
    }

    pub fn serialize_ctrbc(&self)->Vec<u8>{
        let beacon_without_wss = BeaconMsg{
            origin:self.origin,
            round:self.round,
            wss:None,
            root_vec:self.root_vec.clone(),
            appx_con:self.appx_con.clone(),
            degree_test_coeffs:self.degree_test_coeffs.clone(),
            mask_shares:None,
            f_large_shares:None,
        };
        beacon_without_wss.serialize()
    }

    fn serialize(&self)->Vec<u8>{
        bincode::serialize(self).expect("Serialization failed")
    }

    pub fn deserialize(bytes:&[u8])->Self{
        let c:Self = bincode::deserialize(bytes)
            .expect("failed to decode the protocol message");
        c.init()
    }

    fn init(self) -> Self {
        match self {
            _x=>_x
        }
    }

    pub fn verify_proofs(&self,hf:&HashState) -> bool{
        if self.wss.is_some(){
            let wssmsg = self.wss.as_ref().unwrap();
            let mps = Proof::validate_batch(&wssmsg.mps, hf);
            if !mps{
                log::error!("Merkle proof verification failed for wssmsg sent by {}",wssmsg.origin);
                return false;
            }
            // Three leaf formats share this function:
            //   * PPT two-field BigUint path (`mask_shares` AND
            //     `f_large_shares` both present): the committed leaf
            //     binds (f_share, g_share, f_large, nonce) via the
            //     4-field `avss_commit_leaf`. This is the historical
            //     default.
            //   * PPT two-field GF(2^w) path (`mask_shares` present,
            //     `f_large_shares == None`): commit 7 of the GF(2^w)
            //     migration. Subfield closure makes `f_large = f_share`
            //     byte-for-byte, so the dealer skips the redundant
            //     channel; the leaf is 3-field `avss_commit_leaf_gf2`.
            //   * Legacy / non-two-field beacons (no mask): leaf is
            //     `hash(secret, nonce)`, as before.
            // Branching on the presence of the two-field fields keeps
            // all three protocol modes working off the same shared
            // `BeaconMsg`.
            match (self.mask_shares.as_ref(), self.f_large_shares.as_ref()) {
                (Some(mask), maybe_f_large) => {
                    if mask.len() != wssmsg.secrets.len()
                        || wssmsg.nonces.len() != wssmsg.secrets.len()
                    {
                        log::error!("mismatched per-coin lengths for commitment leaf (wss from {})", wssmsg.origin);
                        return false;
                    }
                    if let Some(fl) = maybe_f_large {
                        if fl.len() != wssmsg.secrets.len() {
                            log::error!("mismatched f_large length for commitment leaf (wss from {})", wssmsg.origin);
                            return false;
                        }
                    }
                    for (coin, pf) in wssmsg.mps.iter().enumerate() {
                        let f_large_ref = maybe_f_large.map(|fl| &fl[coin]);
                        let leaf = avss_commit_leaf_auto(
                            &wssmsg.secrets[coin],
                            &mask[coin],
                            f_large_ref,
                            &wssmsg.nonces[coin],
                        );
                        if pf.item() != leaf {
                            log::error!("Commitment does not match element in proof for wssmsg sent by {}",wssmsg.origin);
                            return false;
                        }
                    }
                }
                _ => {
                    // Legacy leaf = hash(secret, nonce).
                    let commitments = hf.hash_batch(wssmsg.secrets.clone(), wssmsg.nonces.clone());
                    for (pf, comm) in wssmsg.mps.iter().zip(commitments.into_iter()) {
                        if pf.item() != comm {
                            log::error!("Commitment does not match element in proof for wssmsg sent by {}",wssmsg.origin);
                            return false;
                        }
                    }
                }
            }
        }
        true
    }
}

#[derive(Debug,Serialize,Deserialize,Clone)]
pub struct CTRBCMsg{
    pub shard:Vec<u8>,
    pub mp:Proof,
    pub round:u32,
    pub origin:Replica
}

impl CTRBCMsg {
    pub fn new(shard:Vec<u8>,mp:Proof,round:u32,origin:Replica)->Self{
        CTRBCMsg { shard: shard, mp: mp, round: round, origin: origin }
    }

    pub fn verify_mr_proof(&self,hf:&HashState) -> bool{
        let hash_of_shard:[u8;32] = do_hash(&self.shard.as_slice());
        hash_of_shard == self.mp.item().clone() && self.mp.validate(hf)
    }
}

#[derive(Debug,Serialize,Deserialize,Clone)]
pub enum CoinMsg{
    AVSSSend(BeaconMsg, Hash, Replica, Round),
    AVSSReady(Replica, Hash, Replica, Round),
    AVSSComplete(Replica, Hash, Replica, Round),
    CTRBCInit(BeaconMsg,CTRBCMsg),
    CTRBCEcho(CTRBCMsg,Hash,Replica),
    CTRBCReady(CTRBCMsg,Hash,Replica),
    CTRBCReconstruct(CTRBCMsg,Hash,Replica),
    GatherEcho(GatherMsg,Replica,Round),
    GatherEcho2(GatherMsg,Replica,Round),
    BinaryAAEcho(Vec<(Round,Vec<(Replica,Vec<u8>)>)>,Replica,Round),
    BinaryAAEcho2(Vec<(Round,Vec<(Replica,Vec<u8>)>)>,Replica,Round),
    // Legacy per-coin reconstruction message (kept for compatibility / replay paths).
    BeaconConstruct(BatchWSSReconMsg,Replica,Replica,Round),

    // New batched reconstruction message: one network broadcast can carry many coin packets.
    BatchBeaconConstruct(BatchBeaconConstructMsg,Replica,Round),

    // Post-ACS accountability multicast containing the sender's locally exposed share set.
    // In step-3 we may resend this as a growing snapshot as more coins recover.
    MulticastRecoveredShares(MulticastRecoveredSharesMsg,Replica,Round),

    BeaconValue(Round,Replica,u128),

    /// Legacy quasi-ACS messages from the early refactor. New code MUST NOT
    /// use these; they are kept only so that older binaries can still
    /// parse the wire format. The PPT path now uses the
    /// `ACSPropose / ACSWitness1 / ACSWitness2` triple below.
    ACSInit((Replica,Round,Vec<Replica>)),
    ACSOutput((Replica,Round,Vec<Replica>)),

    /// PPT ACS Phase 1 — PROPOSE.
    /// `(round, sender, dealers)`: the sender publishes the set of dealers it
    /// has locally observed as AVSS-completed. Receivers buffer/validate the
    /// proposal: a proposal is *externally valid* iff every dealer in
    /// `dealers` is also AVSS-completed in the receiver's local view (by AVSS
    /// totality this becomes true eventually for any honest proposer).
    ACSPropose(Round, Replica, Vec<Replica>),

    /// PPT ACS Phase 2 — WITNESS1.
    /// `(round, sender, validated_proposers)`: after delivering n-f valid
    /// proposals, the sender publishes the set of *proposer IDs* whose
    /// proposals it has validated.
    ACSWitness1(Round, Replica, Vec<Replica>),

    /// PPT ACS Phase 3 — WITNESS2.
    /// `(round, sender, witnessed_w1_senders)`: after delivering n-f
    /// `Witness1` messages whose proposer-sets are subsets of the local
    /// validated set, the sender publishes the IDs of those Witness1 senders.
    /// Once a node sees n-f matching Witness2 messages it finalizes the ACS
    /// decision deterministically (see `acs::decide`).
    ACSWitness2(Round, Replica, Vec<Replica>),

    /// PPT ACS replacement: Cachin-Tessaro / Bracha RBC + Mostefaoui-
    /// Moumen-Raynal ABA. The triple below carries the wire types
    /// for the new ACS pipeline:
    ///
    ///   - `ACSRbcSend(round, dealer_proposer, bytes)` — the SEND
    ///     phase of Bracha RBC. `dealer_proposer` is the *proposer*
    ///     (i.e. which RBC instance this byte stream belongs to);
    ///     the wrapper-level sender field is the actual broadcaster.
    ///   - `ACSRbcEcho(round, dealer_proposer, payload_hash)` —
    ///     ECHO of the SEND with hash-binding.
    ///   - `ACSRbcReady(round, dealer_proposer, payload_hash)` —
    ///     READY threshold message.
    ///   - `ACSAbaBval(round, aba_instance_id, aba_round, value)` —
    ///     MMR ABA BVAL message. `aba_instance_id` selects which of
    ///     the n parallel ABA instances the message belongs to.
    ///   - `ACSAbaAux(round, aba_instance_id, aba_round, value)` —
    ///     MMR ABA AUX message.
    ///
    /// All inputs are signature-free (PQ-safe): the only crypto
    /// material is `payload_hash`, which is a pure SHA-256-class
    /// hash of the RBC payload bytes (used to bind ECHO/READY back
    /// to a specific SEND content; nothing more).
    ACSRbcSend(Round, Replica, Vec<u8>),
    ACSRbcEcho(Round, Replica, Hash),
    ACSRbcReady(Round, Replica, Hash),
    ACSAbaBval(Round, Replica, u64, bool),
    ACSAbaAux(Round, Replica, u64, bool),

    /// Shoup-Smart 2024 Π_SecMsgDst (Sec 4.3) wire types for AVSS
    /// share distribution. The five variants below replace the
    /// per-recipient `AVSSSend(BeaconMsg, ...)` cleartext unicast
    /// once commit 7 cuts the dealer over. The encoding is:
    ///
    ///   - `AVSSSecMsgPublicCommit(msg)` — broadcast once per
    ///     dealer per round; carries the public Merkle roots,
    ///     degree-test coefficients, and transcript-binding hash
    ///     that used to be duplicated across n cleartext
    ///     `AVSSSend` packets.
    ///   - `AVSSSecMsgKey*` and `AVSSSecMsgCipher*` — opaque
    ///     bincode-encoded byte payloads carrying
    ///     `Vec<DispersalEntry>` (key) / `Vec<DispersalEntry>`
    ///     (cipher) for dispersal, `EchoPayload` for echo, and
    ///     a bare meta-root `Hash` for vote. `(round, dealer)`
    ///     identifies the SecMsgDst instance; the wrapper-level
    ///     wire sender is the actual broadcaster of the message.
    ///
    /// All payloads are PQ-safe: only `do_hash` + Merkle proofs +
    /// Reed-Solomon over GF(2^8) (no DL/pairing/RSA primitives).
    AVSSSecMsgPublicCommit(AvssPublicCommitMsg),
    AVSSSecMsgKeyDispersal(Round, Replica, Vec<u8>),
    AVSSSecMsgKeyEcho(Round, Replica, Vec<u8>),
    AVSSSecMsgKeyVote(Round, Replica, Hash),
    AVSSSecMsgCipherDispersal(Round, Replica, Vec<u8>),
    AVSSSecMsgCipherEcho(Round, Replica, Vec<u8>),
    AVSSSecMsgCipherVote(Round, Replica, Hash),

    /// ACS common-coin reveal (PPT problem-1 fix: unpredictable
    /// hash-based async common coin).
    ///
    /// `ACSCoinReveal(acs_round, aba_round, packet)`: the wire sender
    /// reveals its Shamir shares of the sealed coin-secrets for
    /// `aba_round`, one per dealer in the previous round's
    /// ACS-decided set. The coin value `C = Σ_d reconstruct(
    /// c_{d,aba_round})` stays hidden until f+1 honest reveals land —
    /// and honest nodes only reveal AFTER fixing their `aba_round`
    /// AUX — so the adversary cannot predict the coin before honest
    /// AUX are committed, which is what MMR ABA termination requires.
    ACSCoinReveal(Round, u64, BatchWSSReconMsg),

    /// Lite AVSS transport (PPT pluggable-transport mode `lite`,
    /// default). Carries the dealer-to-recipient confidential
    /// `AvssRecipientPayload` (bincode `Vec<u8>`) as a single direct
    /// unicast per recipient, paired with a broadcast
    /// `AVSSSecMsgPublicCommit` for the shared public Merkle roots +
    /// degree-test coefficients.
    ///
    /// `AVSSPrivatePayload(round, dealer, payload_bytes)`: the
    /// wrapper-level `WrapperMsg.sender` MUST equal `dealer` (sender
    /// binding, enforced receiver-side). This is the performance-
    /// oriented alternative to the SS-AVSS Sec 4.3 `AVSSSecMsg*`
    /// transport: PPT does not need Sec 4.3 application-layer
    /// encryption (shares are unicast point-to-point and revealed at
    /// reconstruction anyway), so the lite transport reduces the AVSS
    /// phase from O(n^2) to O(n) wire messages per dealer per round.
    /// PQ-safety unchanged (no new primitives).
    AVSSPrivatePayload(Round, Replica, Vec<u8>),
}

/// Public AVSS commitment broadcast once per (round, dealer).
///
/// Replaces the duplicated public fields previously stuffed into
/// every cleartext `BeaconMsg` (one per recipient): every honest
/// node that receives this commit ends up with the same
/// `(root_vec, degree_test_coeffs, transcript_root)` triple.
///
/// The `transcript_root` is `do_hash(canonical(round, dealer,
/// root_vec, degree_test_coeffs))` and serves the same binding
/// role as the previous `transcript_root = do_hash(BeaconMsg
/// .serialize_ctrbc())` — once a node has cached this commit,
/// any per-recipient share that recovers via Π_SecMsgDst is
/// validated against the cached `root_vec` and `degree_test_coeffs`.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct AvssPublicCommitMsg {
    pub origin: Replica,
    pub round: Round,
    pub root_vec: Vec<Hash>,
    pub degree_test_coeffs: Vec<Vec<Val>>,
    pub transcript_root: Hash,
}

impl AvssPublicCommitMsg {
    pub fn new(
        origin: Replica,
        round: Round,
        root_vec: Vec<Hash>,
        degree_test_coeffs: Vec<Vec<Val>>,
    ) -> Self {
        // Compute transcript_root deterministically over the
        // canonical bincode encoding of the public fields.
        // Receivers must recompute this and compare on receipt.
        let canonical = bincode::serialize(&(
            origin,
            round,
            &root_vec,
            &degree_test_coeffs,
        ))
        .expect("bincode serialize public-commit canonical");
        let transcript_root = do_hash(&canonical);
        Self {
            origin,
            round,
            root_vec,
            degree_test_coeffs,
            transcript_root,
        }
    }

    /// Recompute and verify the binding `transcript_root`. Returns
    /// false if a Byzantine sender tampered with the commit.
    pub fn verify_transcript_root(&self) -> bool {
        let canonical = bincode::serialize(&(
            self.origin,
            self.round,
            &self.root_vec,
            &self.degree_test_coeffs,
        ))
        .expect("bincode serialize public-commit canonical");
        do_hash(&canonical) == self.transcript_root
    }
}

/// Per-recipient confidential AVSS payload — bincode-serialized
/// and shipped through Π_SecMsgDst's encrypted channel. After a
/// receiver completes Π_SecMsgDst, the delivered plaintext bytes
/// deserialize back into this struct, which is then validated
/// against the cached `AvssPublicCommitMsg` and stored as the
/// node's local AVSS dealer packet.
///
/// This is exactly the per-recipient subset of `BeaconMsg` /
/// `BatchWSSMsg` used by the legacy `AVSSSend` path:
///
/// | Field            | Field on legacy `BatchWSSMsg`/`BeaconMsg` |
/// |------------------|-------------------------------------------|
/// | `secrets`        | `BatchWSSMsg.secrets` (f(j+1) mod p)      |
/// | `nonces`         | `BatchWSSMsg.nonces` (nonce mod q)        |
/// | `mask_shares`    | `BeaconMsg.mask_shares` (g(j+1) mod q)    |
/// | `f_large_shares` | `BeaconMsg.f_large_shares` (f(j+1) mod q) |
/// | `mps`            | `BatchWSSMsg.mps` (per-coin Merkle proofs)|
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct AvssRecipientPayload {
    pub secrets: Vec<Val>,
    pub nonces: Vec<Val>,
    pub mask_shares: Vec<Val>,
    /// `None` in GF(2^w) mode (commit 7): subfield closure makes
    /// `f_large_shares[i] == secrets[i]` byte-for-byte, so the
    /// redundant channel is dropped on the wire and the receiver
    /// derives `f_large` locally from `secrets`. `Some(_)` in
    /// BigUint mode (legacy default).
    pub f_large_shares: Option<Vec<Val>>,
    pub mps: Vec<Proof>,
}

impl AvssRecipientPayload {
    pub fn new(
        secrets: Vec<Val>,
        nonces: Vec<Val>,
        mask_shares: Vec<Val>,
        f_large_shares: Option<Vec<Val>>,
        mps: Vec<Proof>,
    ) -> Self {
        Self {
            secrets,
            nonces,
            mask_shares,
            f_large_shares,
            mps,
        }
    }

    pub fn serialize_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("bincode serialize AvssRecipientPayload")
    }

    pub fn deserialize_bytes(bytes: &[u8]) -> Option<Self> {
        bincode::deserialize(bytes).ok()
    }
}

#[derive(Debug,Serialize,Deserialize,Clone)]
pub struct BatchWSSMsg{
    pub secrets: Vec<Val>,
    pub origin: Replica,
    pub nonces: Vec<Val>,
    pub mps: Vec<Proof>,
    pub empty: bool
}

impl BatchWSSMsg {
    pub fn new(origin:Replica,secrets:Vec<Val>,nonces:Vec<Val>,mps:Vec<Proof>)->Self{
        BatchWSSMsg{
            secrets,
            origin,
            nonces,
            mps,
            empty:false
        }
    }
    pub fn empty()->BatchWSSMsg{
        BatchWSSMsg{
            secrets:Vec::new(),
            origin:0,
            nonces:Vec::new(),
            mps:Vec::new(),
            empty:false
        }
    }
}

#[derive(Debug,Serialize,Deserialize,Clone)]
pub struct BatchWSSReconMsg{
    pub origin: Replica,
    pub secrets: Vec<Val>,
    pub nonces: Vec<Val>,
    pub origins: Vec<Replica>,
    pub mps: Vec<Proof>,
    /// g(i) shares aligned with `origins`
    #[serde(default)]
    pub mask_shares: Vec<Val>,
    /// f(i) evaluated in the large field, aligned with `origins`.
    /// `None` in GF(2^w) mode (commit 7) — subfield closure makes
    /// `f_large_shares[i] == secrets[i]`. `Some(_)` in BigUint
    /// mode.
    #[serde(default)]
    pub f_large_shares: Option<Vec<Val>>,
    pub empty: bool
}

impl BatchWSSReconMsg {
    pub fn new(
        origin:Replica,
        secrets:Vec<Val>,
        nonces:Vec<Val>,
        origin_replicas:Vec<Replica>,
        mps:Vec<Proof>,
        mask_shares:Vec<Val>,
        f_large_shares:Option<Vec<Val>>,
    )->Self{
        BatchWSSReconMsg{
            secrets,
            origin,
            nonces,
            origins:origin_replicas,
            mps,
            mask_shares,
            f_large_shares,
            empty:false
        }
    }
}

#[derive(Debug,Serialize,Deserialize,Clone)]
pub struct RecoveredCoinSharesMsg {
    pub coin_num: usize,
    pub packet: BatchWSSReconMsg,
}

#[derive(Debug,Serialize,Deserialize,Clone)]
pub struct BatchBeaconConstructMsg {
    pub origin: Replica,
    pub round: Round,
    pub packets: Vec<RecoveredCoinSharesMsg>,
}


#[derive(Debug,Serialize,Deserialize,Clone)]
pub struct MulticastRecoveredSharesMsg {
    pub origin: Replica,
    pub round: Round,
    pub packets: Vec<RecoveredCoinSharesMsg>,
}

#[derive(Debug,Serialize,Deserialize,Clone)]
pub struct WSSMsg {
    pub origin:Replica,
    pub secret:Val,
    pub nonce:Val,
    pub mp:Proof
}

impl WSSMsg {
    pub fn new(origin:Replica,secret:Val,nonce:Val,mp:Proof)->Self{
        WSSMsg {
            secret,
            origin,
            nonce,
            mp
        }
    }
}

#[derive(Debug,Serialize,Deserialize,Clone)]
pub struct GatherMsg{
    pub nodes: Vec<Replica>,
}

#[derive(Debug,Serialize,Deserialize,Clone)]
pub struct WrapperMsg{
    pub protmsg: CoinMsg,
    pub sender:Replica,
    pub mac:Hash,
    pub round:Round
}

impl WrapperMsg{
    pub fn new(msg:CoinMsg,sender:Replica, sk: &[u8],round:Round) -> Self{
        let new_msg = msg.clone();
        let bytes = bincode::serialize(&new_msg).expect("Failed to serialize protocol message");
        let mac = do_mac(&bytes.as_slice(), sk);
        Self{
            protmsg: new_msg,
            mac,
            sender,
            round
        }
    }
}

impl WireReady for WrapperMsg{
    fn from_bytes(bytes: &[u8]) -> Self {
        let c:Self = bincode::deserialize(bytes)
            .expect("failed to decode the protocol message");
        c.init()
    }

    fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Failed to serialize client message")
    }

    fn init(self) -> Self {
        match self {
            _x=>_x
        }
    }
}

// ---------------------------------------------------------------------
// Unit tests for the Shoup-Smart 2024 SecMsgDst-AVSS wire types.
// ---------------------------------------------------------------------

#[cfg(test)]
mod shoup_smart_avss_wire_tests {
    use super::*;

    fn sample_root(byte: u8) -> Hash {
        let mut h = [0u8; 32];
        for (i, b) in h.iter_mut().enumerate() {
            *b = byte.wrapping_add(i as u8);
        }
        h
    }

    fn sample_val(byte: u8) -> Val {
        let mut v = [0u8; 32];
        for (i, b) in v.iter_mut().enumerate() {
            *b = byte ^ (i as u8);
        }
        v
    }

    #[test]
    fn avss_public_commit_msg_bincode_roundtrip() {
        let m = AvssPublicCommitMsg::new(
            7,
            42,
            vec![sample_root(0xAA), sample_root(0xBB), sample_root(0xCC)],
            vec![
                vec![sample_val(0x01), sample_val(0x02)],
                vec![sample_val(0x03), sample_val(0x04)],
                vec![sample_val(0x05), sample_val(0x06)],
            ],
        );
        let bytes = bincode::serialize(&m).expect("ser");
        let parsed: AvssPublicCommitMsg = bincode::deserialize(&bytes).expect("de");
        assert_eq!(parsed, m);
        assert!(parsed.verify_transcript_root());
    }

    #[test]
    fn avss_public_commit_transcript_root_detects_tamper() {
        let mut m = AvssPublicCommitMsg::new(
            3,
            12,
            vec![sample_root(0x10)],
            vec![vec![sample_val(0x20)]],
        );
        // Pristine commit verifies.
        assert!(m.verify_transcript_root());
        // Tampering with public fields without recomputing the
        // binding hash → verify must fail.
        m.root_vec.push(sample_root(0x99));
        assert!(!m.verify_transcript_root());
    }

    #[test]
    fn avss_recipient_payload_serialize_roundtrip() {
        // Build a small payload with empty Merkle proofs (Proof
        // serialisation is exercised in ppt_beacon tests; here we
        // just need the AvssRecipientPayload struct itself).
        let p = AvssRecipientPayload::new(
            vec![sample_val(0x11), sample_val(0x12)],
            vec![sample_val(0x21), sample_val(0x22)],
            vec![sample_val(0x31), sample_val(0x32)],
            vec![sample_val(0x41), sample_val(0x42)],
            Vec::new(), // no Merkle proofs in this minimal example
        );
        let bytes = p.serialize_bytes();
        let parsed = AvssRecipientPayload::deserialize_bytes(&bytes)
            .expect("AvssRecipientPayload deserialize");
        assert_eq!(parsed, p);
    }

    #[test]
    fn avss_recipient_payload_rejects_garbage() {
        let parsed = AvssRecipientPayload::deserialize_bytes(&[0xFFu8; 4]);
        assert!(parsed.is_none(), "garbage bytes must not deserialize");
    }

    #[test]
    fn coin_msg_secmsg_variants_bincode_roundtrip() {
        let commit = AvssPublicCommitMsg::new(
            1,
            5,
            vec![sample_root(0x01)],
            vec![vec![sample_val(0x02)]],
        );
        let cases = vec![
            CoinMsg::AVSSSecMsgPublicCommit(commit),
            CoinMsg::AVSSSecMsgKeyDispersal(7, 2, vec![1u8, 2u8, 3u8]),
            CoinMsg::AVSSSecMsgKeyEcho(7, 2, vec![4u8, 5u8]),
            CoinMsg::AVSSSecMsgKeyVote(7, 2, sample_root(0xDE)),
            CoinMsg::AVSSSecMsgCipherDispersal(7, 2, vec![6u8, 7u8]),
            CoinMsg::AVSSSecMsgCipherEcho(7, 2, vec![8u8]),
            CoinMsg::AVSSSecMsgCipherVote(7, 2, sample_root(0xAD)),
            CoinMsg::AVSSPrivatePayload(
                7,
                2,
                vec![9u8, 10u8, 11u8, 12u8, 13u8],
            ),
        ];
        for c in cases {
            let bytes = bincode::serialize(&c).expect("ser");
            let parsed: CoinMsg = bincode::deserialize(&bytes).expect("de");
            // CoinMsg doesn't implement PartialEq directly; check
            // structurally via bincode equality (the canonical way
            // a network peer would compare).
            let bytes2 = bincode::serialize(&parsed).expect("re-ser");
            assert_eq!(bytes, bytes2);
        }
    }

    #[test]
    fn private_payload_carries_recipient_bytes_unchanged() {
        // The lite transport ships AvssRecipientPayload's bincode-
        // serialized bytes verbatim inside AVSSPrivatePayload.
        // Round-trip a real-shaped payload to confirm the wire
        // format does not corrupt it.
        let payload = AvssRecipientPayload::new(
            vec![sample_val(0x11), sample_val(0x12)],
            vec![sample_val(0x21), sample_val(0x22)],
            vec![sample_val(0x31), sample_val(0x32)],
            vec![sample_val(0x41), sample_val(0x42)],
            Vec::new(),
        );
        let bytes = payload.serialize_bytes();
        let wire = CoinMsg::AVSSPrivatePayload(11, 5, bytes.clone());
        let ser = bincode::serialize(&wire).expect("ser");
        let parsed: CoinMsg = bincode::deserialize(&ser).expect("de");
        let extracted_bytes = match parsed {
            CoinMsg::AVSSPrivatePayload(11, 5, b) => b,
            other => panic!("wrong variant after deserialize: {:?}",
                std::mem::discriminant(&other)),
        };
        assert_eq!(extracted_bytes, bytes);
        let recovered = AvssRecipientPayload::deserialize_bytes(&extracted_bytes)
            .expect("recovered payload deserializes");
        assert_eq!(recovered, payload);
    }
}
