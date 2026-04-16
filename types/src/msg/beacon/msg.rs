use crypto::{hash::{Hash, do_mac, do_hash}, aes_hash::{Proof, HashState, HASH_SIZE}};
use serde::{Serialize, Deserialize};

use crate::{WireReady, Round};

use super::{Replica};

pub type Val = [u8; HASH_SIZE];

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
    pub fn new_two_field(
        origin:Replica,
        round:Round,
        wss_msg:BatchWSSMsg,
        root_vec:Vec<Hash>,
        appx_con: Vec<(Round,Vec<(Replica,Val)>)>,
        degree_test_coeffs: Vec<Vec<Val>>,
        mask_shares: Vec<Val>,
        f_large_shares: Vec<Val>,
    )->BeaconMsg{
        BeaconMsg {
            origin,
            round,
            wss: Some(wss_msg),
            root_vec: Some(root_vec),
            appx_con: Some(appx_con),
            degree_test_coeffs: Some(degree_test_coeffs),
            mask_shares: Some(mask_shares),
            f_large_shares: Some(f_large_shares),
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
            let secrets = wssmsg.secrets.clone();
            let nonces = wssmsg.nonces.clone();
            let commitments = hf.hash_batch(secrets, nonces);
            for (pf,comm) in wssmsg.mps.iter().zip(commitments.into_iter()){
                if pf.item() != comm{
                    log::error!("Commitment does not match element in proof for wssmsg sent by {}",wssmsg.origin);
                    return false;
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
    ACSInit((Replica,Round,Vec<Replica>)),
    ACSOutput((Replica,Round,Vec<Replica>)),
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
    /// f(i) evaluated in the large field, aligned with `origins`
    #[serde(default)]
    pub f_large_shares: Vec<Val>,
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
        f_large_shares:Vec<Val>,
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
