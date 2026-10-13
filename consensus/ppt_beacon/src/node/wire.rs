//! PPTB-only extension messages. Existing CoinMsg discriminants stay unchanged.
use serde::{Deserialize, Serialize};
use types::beacon::{CoinMsg, WrapperMsg};
use types::{Replica, Round};
use aes::{Aes256, cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray}};
use rand::RngCore;
use crypto::hash::Hash;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum RbcScope { PublicCommit, AcsProposal }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum RbcMessage {
    Send(Vec<u8>), Echo(Hash), Ready(Hash), Request(Hash), Payload(Hash, Vec<u8>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) enum ForwardTag { Complaint, Assist, Report }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PublicBundle {
    /// Version 2 uses one GF2 main-batch h and a compact main mask.
    pub version: u16,
    pub public: types::beacon::AvssPublicCommitMsg,
    /// Exact roots of the SecMsg key/cipher vectors. None for Lite comparisons.
    pub secmsg_roots: Option<(Hash, Hash)>,
    /// Independent sealed-reserve keys: never disclosed by the batch audit.
    pub reserve_roots: Option<(Hash, Hash)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum RmdPacket {
    Dispersal(Vec<super::shoup_smart::rel_msg_dst::DispersalEntry>),
    Echo(super::shoup_smart::rel_msg_dst::EchoPayload),
    Vote(Hash),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum PptWire {
    TransformedShares { round: Round, dealers: Vec<Replica>, values: Vec<types::beacon::Val> },
    AuditDisclosure { round: Round, dealers: Vec<Replica>, entries: Vec<super::full_audit::DealerDisclosure> },
    AuditCertificate { round: Round, dealers: Vec<Replica>, rows: Vec<(Replica, Vec<super::full_audit::DealerDisclosure>)> },
    AuditRecovered { round: Round },
    ReserveTransport { round: Round, dealer: Replica, channel: super::shoup_smart::sec_msg_dst::SecMsgChannel, packet: RmdPacket },
    ReserveRequest { round: Round, dealer: Replica, recipient: Replica },
    ReserveRecovered { round: Round, dealer: Replica },
    Rbc { scope: RbcScope, round: Round, proposer: Replica, message: RbcMessage },
    AwssRequest { round: Round, dealer: Replica, root: Hash, recipient: Replica },
    AwssRecovered { round: Round, dealer: Replica, root: Hash },
    AwssForward { round: Round, dealer: Replica, root: Hash, source: Replica,
        recipient: Replica, tag: ForwardTag,
        proof: super::shoup_smart::sec_msg_dst::ForwardMessagePayload },
    AwssChannelForward { round: Round, dealer: Replica, root: Hash, source: Replica,
        recipient: Replica, channel: super::shoup_smart::sec_msg_dst::SecMsgChannel,
        proof: super::shoup_smart::rel_msg_dst::ForwardPayload },
    Private {
        sender: Replica,
        recipient: Replica,
        round: Round,
        nonce: [u8; 32],
        ciphertext: Vec<u8>,
    },
}

pub(crate) fn encode(message: &PptWire) -> CoinMsg {
    CoinMsg::PPTBExtension(bincode::serialize(message).expect("PPTB wire serialization"))
}

/// A fresh AES-256 counter stream per packet, with a domain-separated HMAC
/// derivation from the existing 32-byte pairwise secret. WrapperMsg authenticates
/// the complete encrypted envelope before decryption (encrypt-then-MAC).
fn crypt(key: &[u8], sender: Replica, recipient: Replica, round: Round,
         nonce: &[u8; 32], bytes: &mut [u8]) {
    let mut context = b"PPTB_PRIVATE_AES256_v1::".to_vec();
    context.extend_from_slice(&(sender as u64).to_be_bytes());
    context.extend_from_slice(&(recipient as u64).to_be_bytes());
    context.extend_from_slice(&round.to_be_bytes());
    context.extend_from_slice(nonce);
    let encryption_key = crypto::hash::do_mac(&context, key);
    let cipher = Aes256::new(GenericArray::from_slice(&encryption_key));
    for (counter, chunk) in bytes.chunks_mut(16).enumerate() {
        let mut block = GenericArray::clone_from_slice(&(counter as u128).to_be_bytes());
        cipher.encrypt_block(&mut block);
        for (value, mask) in chunk.iter_mut().zip(block.iter()) { *value ^= mask; }
    }
}

pub(crate) fn protect(message: CoinMsg, sender: Replica, recipient: Replica,
                      round: Round, key: &[u8]) -> WrapperMsg {
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    let mut ciphertext = bincode::serialize(&message).expect("PPTB plaintext serialization");
    crypt(key, sender, recipient, round, &nonce, &mut ciphertext);
    WrapperMsg::new(encode(&PptWire::Private { sender, recipient, round, nonce, ciphertext }),
                    sender, key, round)
}

/// Caller must verify WrapperMsg's MAC before invoking this function.
pub(crate) fn unprotect(wrapper: &WrapperMsg, recipient: Replica, key: &[u8]) -> Option<CoinMsg> {
    let bytes = match &wrapper.protmsg { CoinMsg::PPTBExtension(bytes) => bytes, _ => return None };
    let envelope: PptWire = bincode::deserialize(bytes).ok()?;
    match envelope {
        PptWire::Private { sender, recipient: target, round, nonce, mut ciphertext }
            if sender == wrapper.sender && target == recipient && round == wrapper.round => {
                crypt(key, sender, target, round, &nonce, &mut ciphertext);
                let message: CoinMsg = bincode::deserialize(&ciphertext).ok()?;
                // Reject nested encryption envelopes; one MAC/decrypt boundary per packet.
                if let CoinMsg::PPTBExtension(bytes) = &message {
                    if matches!(bincode::deserialize::<PptWire>(bytes), Ok(PptWire::Private { .. })) {
                        return None;
                    }
                }
                Some(message)
            }
        _ => None,
    }
}
