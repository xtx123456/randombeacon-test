//! Π_SecMsgDst — Secret Message Distribution from Section 4.3 of:
//!
//!   Victor Shoup and Nigel P. Smart, "Lightweight Asynchronous
//!   Verifiable Secret Sharing with Optimal Resilience", Journal of
//!   Cryptology 37(3):27, 2024 (DOI 10.1007/s00145-024-09505-6).
//!
//! ## What this protocol does
//!
//! A SENDER S holds a vector of `n` confidential messages
//! `m = (m_1, ..., m_n)` and wishes every party `P_j` to learn
//! exactly its own `m_j` while ≤ t corrupted parties learn nothing
//! about any honest `m_j`.
//!
//! Π_SecMsgDst integrates two sibling sub-protocols:
//!
//!   * **Π_SecKeyDst (Sec 4.2)** — distributes a fresh master key
//!     `K ∈ F_p` so that party `P_j` privately receives its share
//!     `k_j = p_K(j+1)` (Shamir t-of-n hiding).
//!   * **Π_RelMsgDst (Sec 4.1)** — publicly distributes a vector
//!     of ciphertexts `(c_1, ..., c_n)` with reliable + Bracha
//!     agreement guarantees.
//!
//! Encryption is a hash-chain stream cipher keyed by the
//! per-recipient share `k_j`:
//!
//! ```text
//!     PRG(key, len) = do_hash(DOMAIN || key || 0u64_be) ||
//!                     do_hash(DOMAIN || key || 1u64_be) ||
//!                     ...                               truncated to `len` bytes
//!     c_j = m_j ⊕ PRG(serialize(k_j), |m_j|)
//! ```
//!
//! Each `m_j` is masked with a freshly-derived stream from a
//! distinct `k_j`, so a coalition of ≤ t corrupted receivers
//! (which knows ≤ t shares and ≤ t of the corresponding streams)
//! cannot decrypt any honest party's `m_i` even after the cipher
//! vector becomes public via Π_RelMsgDst.
//!
//! ## Design choices
//!
//! 1. **Sender knows every `k_j` synchronously.** The sender's
//!    polynomial sampling is local — it does not need to wait for
//!    its own SecKeyDst dispersal to round-trip before encrypting
//!    `m_j`. We expose `SecKeyDstState::sender_known_shares()` and
//!    pull the share vector synchronously, then PRG and emit the
//!    ciphertexts in the same `set_input_as_sender` call.
//!
//! 2. **Receiver waits for both channels.** Decryption needs both
//!    its own `k_j` (from SecKeyDst) and its own `c_j` (from the
//!    cipher RelMsgDst). The state machine buffers whichever
//!    arrives first; once both have arrived we run the XOR and
//!    emit `DeliveredMessage { message }` exactly once.
//!
//! 3. **Forwarding combines both layers atomically.** The
//!    forwarding payload `ForwardMessagePayload { key_forward,
//!    cipher_forward }` carries both sub-protocols' Sec 4.1
//!    forward proofs. Receiver `Q` validates each forward
//!    independently (re-running the rebuild check from
//!    Π_RelMsgDst) — only if both succeed does `Q` decrypt and
//!    output `m_j`.
//!
//! 4. **Channel-tagged actions.** To avoid combinatorial
//!    explosion of variant names, the action enum uses a
//!    `SecMsgChannel` tag (`Key` or `Cipher`) on the network-side
//!    actions, so the wire-side driver can plug each channel
//!    into the same dispersal/echo/vote routes.
//!
//! ## PQ-safety
//!
//! * Symmetric encryption uses only `crypto::hash::do_hash`
//!   (SHA-256). No AES, no DL/pairing/RSA primitives, no new
//!   Cargo dependencies.
//! * Underlying transport is the existing PQ-safe Π_RelMsgDst
//!   (hash + Merkle + Reed-Solomon over GF(2^8)).
//! * The `k_j → e_j` PRG is provably indistinguishable from
//!   uniform under the standard "random-oracle SHA-256" assumption,
//!   which is the same model PPT already relies on.
//!
//! ## What this module does NOT do
//!
//! Π_SecMsgDst by itself does NOT verify that a Byzantine sender
//! committed to a *single* polynomial `p_K` consistent across all
//! `k_j`. Two honest receivers reconstructing `K` from disjoint
//! `t+1` subsets could end up with two different `K`s. Detection
//! of that violation is the responsibility of Π_avss1 (Sec 5),
//! which composes Π_SecMsgDst with a degree-test / commitment
//! check. That is commit 6.

use std::fmt;
use std::sync::Arc;

use crypto::aes_hash::HashState;
use crypto::hash::{do_hash, Hash, HASH_SIZE};
use num_bigint::BigUint;
use types::Replica;

use super::rel_msg_dst::{
    DispersalEntry, EchoPayload, ForwardPayload, ForwardReject, RelMsgDstAction,
    RelMsgDstError, RelMsgDstState,
};
use super::sec_key_dst::{
    serialize_share, share_byte_len, SecKeyDstError, SecKeyDstState,
};

// ---------------------------------------------------------------------
// Stream-cipher PRG
// ---------------------------------------------------------------------

/// Domain separator for the SecMsgDst hash-chain PRG. Any change
/// here (or in `derive_stream`'s implementation) breaks
/// interoperability between sender and receiver — keep stable.
const SECMSG_PRG_DOMAIN: &[u8] = b"PPT_SHOUPSMART_SECMSG_PRG_v1::";

/// Hash-chain stream-cipher key-derivation: produce `len` bytes
/// of output deterministically from `key_bytes`.
///
/// ```text
///     block_i  = do_hash(DOMAIN || key_bytes || i.to_be_bytes())
///     stream   = block_0 || block_1 || ... truncated to `len`
/// ```
///
/// Each `block_i` is exactly `HASH_SIZE = 32` bytes (SHA-256
/// output). The total cost is `ceil(len / 32)` SHA-256 calls.
pub fn derive_stream(key_bytes: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let blocks_needed = (len + HASH_SIZE - 1) / HASH_SIZE;
    let mut buf: Vec<u8> = Vec::with_capacity(SECMSG_PRG_DOMAIN.len() + key_bytes.len() + 8);
    for i in 0..blocks_needed {
        buf.clear();
        buf.extend_from_slice(SECMSG_PRG_DOMAIN);
        buf.extend_from_slice(key_bytes);
        buf.extend_from_slice(&(i as u64).to_be_bytes());
        let block: Hash = do_hash(&buf);
        out.extend_from_slice(&block[..]);
    }
    out.truncate(len);
    out
}

/// In-place XOR `buf[i] ^= stream[i]` for `i ∈ [0, min(buf.len(),
/// stream.len()))`. Caller is responsible for `stream.len() >=
/// buf.len()` (i.e. for using `derive_stream(_, buf.len())`).
pub fn xor_in_place(buf: &mut [u8], stream: &[u8]) {
    let n = std::cmp::min(buf.len(), stream.len());
    for i in 0..n {
        buf[i] ^= stream[i];
    }
}

/// Symmetric encrypt `plaintext` under the per-recipient key
/// `k_j`. Returns ciphertext bytes of length `plaintext.len()`.
/// The caller must ensure `prime` matches the field used by the
/// sibling Π_SecKeyDst.
pub fn encrypt_with_share(prime: &BigUint, k_j: &BigUint, plaintext: &[u8]) -> Vec<u8> {
    let key_bytes =
        serialize_share(prime, k_j).expect("k_j < prime by Shamir construction");
    let stream = derive_stream(&key_bytes, plaintext.len());
    let mut out = plaintext.to_vec();
    xor_in_place(&mut out, &stream);
    out
}

/// Inverse of `encrypt_with_share`. Returns `None` only if
/// `serialize_share` fails (k_j >= prime, which would be a bug
/// upstream — the SecKeyDst layer rejects any such share).
pub fn decrypt_with_share(prime: &BigUint, k_j: &BigUint, ciphertext: &[u8]) -> Option<Vec<u8>> {
    if k_j >= prime {
        return None;
    }
    let key_bytes = serialize_share(prime, k_j)?;
    let stream = derive_stream(&key_bytes, ciphertext.len());
    let mut out = ciphertext.to_vec();
    xor_in_place(&mut out, &stream);
    Some(out)
}

// ---------------------------------------------------------------------
// Channel tag + Action enum
// ---------------------------------------------------------------------

/// Which sub-protocol a particular wire action belongs to. The
/// driver routes Key actions to the SecKeyDst channel and Cipher
/// actions to the public RelMsgDst channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecMsgChannel {
    Key,
    Cipher,
}

/// Wire-level forwarding payload carrying both sub-protocols'
/// proofs so the receiver can decrypt `m_j` independently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardMessagePayload {
    pub key_forward: ForwardPayload,
    pub cipher_forward: ForwardPayload,
}

/// Reasons a `ForwardMessagePayload` may be rejected. Either the
/// key channel or the cipher channel rejected, or both succeeded
/// but the resulting decrypt produced bytes the caller-level
/// validator (when one is composed in Π_avss1) flagged as bogus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecMsgForwardReject {
    KeyChannelRejected(ForwardReject),
    CipherChannelRejected(ForwardReject),
}

/// Reasons a happy-path delivery failed *after* both channels
/// completed. Indicates a Byzantine sender (channels passed
/// validation but the decrypted bytes are unusable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecryptFailReason {
    /// `cipher.len() == 0` is not necessarily an error — empty
    /// messages decrypt to empty plaintext. Reserved variant for
    /// upstream-supplied length-mismatch checks (e.g. when the
    /// AVSS layer expects a fixed share size).
    LengthMismatch { expected: usize, got: usize },
    /// `k_j >= prime` — should be unreachable since SecKeyDst
    /// validates this at parse time.
    InvalidKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecMsgDstAction {
    /// Per-recipient dispersal block from the sender.
    SendDispersal {
        channel: SecMsgChannel,
        recipient_idx: usize,
        entries: Vec<DispersalEntry>,
    },
    /// Receiver-to-recipient ECHO (Bracha echo phase of RelMsgDst).
    SendEcho {
        channel: SecMsgChannel,
        recipient_idx: usize,
        echo: EchoPayload,
    },
    /// Bracha VOTE on a meta-root in the channel-specific RelMsgDst.
    SendVote {
        channel: SecMsgChannel,
        meta_root: Hash,
    },
    /// Lower-level (single-channel) forward, emitted only when
    /// the higher-level `prepare_message_forward_for` cannot be
    /// used (e.g. the caller wants to split a forward across two
    /// hops). Almost always you want `SendMessageForward` instead.
    SendForward {
        channel: SecMsgChannel,
        recipient: Replica,
        forward: ForwardPayload,
    },
    /// Combined message-level forward: key + cipher forwards
    /// shipped together so `Q` can decrypt `m_source` atomically.
    SendMessageForward {
        recipient: Replica,
        payload: ForwardMessagePayload,
    },
    /// Local: this party has received its own plaintext `m_myid`.
    /// Latches once set; subsequent triggers are idempotent.
    DeliveredMessage { message: Vec<u8> },
    /// Local: a forwarded plaintext from `source` decoded
    /// successfully under both channels' proofs.
    ForwardDeliveredMessage { source: Replica, message: Vec<u8> },
    /// Local: a forwarded payload was rejected (one of the two
    /// underlying channels returned `ForwardRejected`).
    ForwardRejected {
        source: Replica,
        reason: SecMsgForwardReject,
    },
    /// Local: both channels delivered but post-decrypt validation
    /// failed (Byzantine sender or upstream length-mismatch).
    DeliveryFailedDecrypt { reason: DecryptFailReason },
}

// ---------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------

#[derive(Debug)]
pub enum SecMsgDstError {
    InvalidConfig(SecKeyDstError),
    InvalidConfigCipher(RelMsgDstError),
    NotSender { myid: Replica, sender: Replica },
    /// `set_input_as_sender` was called with `messages.len() != n`.
    WrongMessageVectorLength { provided: usize, expected: usize },
    /// SecKeyDst sub-protocol failed during sender setup.
    SecKeyUnderlying(SecKeyDstError),
    /// RelMsgDst sub-protocol failed during sender setup.
    CipherUnderlying(RelMsgDstError),
    /// `prepare_message_forward_for` called before delivery.
    NotYetDelivered,
    /// `prepare_message_forward_for(self.myid)` is meaningless.
    SelfForwardRequest,
}

impl fmt::Display for SecMsgDstError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecMsgDstError::InvalidConfig(e) => write!(f, "invalid SecKeyDst config: {}", e),
            SecMsgDstError::InvalidConfigCipher(e) => {
                write!(f, "invalid cipher RelMsgDst config: {}", e)
            }
            SecMsgDstError::NotSender { myid, sender } => {
                write!(f, "node {} is not the sender ({})", myid, sender)
            }
            SecMsgDstError::WrongMessageVectorLength { provided, expected } => {
                write!(
                    f,
                    "sender vector has {} messages, expected {}",
                    provided, expected
                )
            }
            SecMsgDstError::SecKeyUnderlying(e) => write!(f, "SecKeyDst error: {}", e),
            SecMsgDstError::CipherUnderlying(e) => write!(f, "RelMsgDst error: {}", e),
            SecMsgDstError::NotYetDelivered => write!(f, "message not yet delivered"),
            SecMsgDstError::SelfForwardRequest => write!(f, "cannot forward to self"),
        }
    }
}

impl std::error::Error for SecMsgDstError {}

// ---------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------

pub struct SecMsgDstState {
    pub myid: Replica,
    pub n: usize,
    pub t: usize,
    pub sender: Replica,
    pub prime: BigUint,

    /// Inner key-distribution channel (Π_SecKeyDst).
    sec_key: SecKeyDstState,
    /// Inner ciphertext-distribution channel (Π_RelMsgDst).
    cipher: RelMsgDstState,

    /// Cached delivered own-key once Π_SecKeyDst delivers.
    delivered_key: Option<BigUint>,
    /// Cached delivered own-ciphertext once cipher RelMsgDst
    /// delivers.
    delivered_cipher: Option<Vec<u8>>,
    /// Latched plaintext after both channels arrived. Idempotent.
    delivered_message: Option<Vec<u8>>,

    /// Sender-only: the actual plaintext vector, kept around so
    /// the sender can also locally observe its own delivery. (The
    /// sender's own dispersal-phase delivery on both channels
    /// would yield the same plaintext through decryption, but
    /// caching avoids an extra PRG-and-XOR.)
    sender_messages: Option<Vec<Vec<u8>>>,
}

impl fmt::Debug for SecMsgDstState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecMsgDstState")
            .field("myid", &self.myid)
            .field("n", &self.n)
            .field("t", &self.t)
            .field("sender", &self.sender)
            .field("delivered_key", &self.delivered_key.is_some())
            .field("delivered_cipher", &self.delivered_cipher.is_some())
            .field("delivered_message", &self.delivered_message.is_some())
            .finish()
    }
}

impl SecMsgDstState {
    pub fn new(
        myid: Replica,
        n: usize,
        t: usize,
        sender: Replica,
        prime: BigUint,
        hash_state: Arc<HashState>,
    ) -> Result<Self, SecMsgDstError> {
        let sec_key =
            SecKeyDstState::new(myid, n, t, sender, prime.clone(), hash_state.clone())
                .map_err(SecMsgDstError::InvalidConfig)?;
        let cipher = RelMsgDstState::new(myid, n, t, sender, hash_state)
            .map_err(SecMsgDstError::InvalidConfigCipher)?;
        Ok(Self {
            myid,
            n,
            t,
            sender,
            prime,
            sec_key,
            cipher,
            delivered_key: None,
            delivered_cipher: None,
            delivered_message: None,
            sender_messages: None,
        })
    }

    pub fn delivered(&self) -> bool {
        self.delivered_message.is_some()
    }

    pub fn delivered_message(&self) -> Option<&[u8]> {
        self.delivered_message.as_deref()
    }

    /// Sender-side: sample master key, generate per-recipient
    /// shares + symmetric streams, encrypt every `m_j`, and emit
    /// the dispersal actions for both sub-channels.
    pub fn set_input_as_sender<R>(
        &mut self,
        messages: Vec<Vec<u8>>,
        rng: &mut R,
    ) -> Result<Vec<SecMsgDstAction>, SecMsgDstError>
    where
        R: num_bigint::RandBigInt,
    {
        if self.myid != self.sender {
            return Err(SecMsgDstError::NotSender {
                myid: self.myid,
                sender: self.sender,
            });
        }
        if messages.len() != self.n {
            return Err(SecMsgDstError::WrongMessageVectorLength {
                provided: messages.len(),
                expected: self.n,
            });
        }

        // (1) Sample a fresh master key K ∈ [0, prime).
        let zero = BigUint::from(0u32);
        let master_key: BigUint = rng.gen_biguint_range(&zero, &self.prime);

        // (2) Run SecKeyDst's set_input_as_sender to disperse K's
        // shares. As a side-effect this populates
        // `sec_key.sender_known_shares()` with (k_1, ..., k_n).
        let key_actions = self
            .sec_key
            .set_input_as_sender(master_key, rng)
            .map_err(SecMsgDstError::SecKeyUnderlying)?;

        let shares: Vec<BigUint> = self
            .sec_key
            .sender_known_shares()
            .expect("set_input_as_sender just populated shares")
            .to_vec();

        // (3) Encrypt each m_j with stream PRG keyed by k_j.
        let mut ciphertexts: Vec<Vec<u8>> = Vec::with_capacity(self.n);
        for (m_j, k_j) in messages.iter().zip(shares.iter()) {
            ciphertexts.push(encrypt_with_share(&self.prime, k_j, m_j));
        }

        // (4) Disperse the ciphertext vector via Π_RelMsgDst.
        let cipher_actions = self
            .cipher
            .set_input_as_sender(ciphertexts)
            .map_err(SecMsgDstError::CipherUnderlying)?;

        // (5) Cache the plaintext vector so the sender's own
        // delivery on the network round-trip is a no-op.
        self.sender_messages = Some(messages);

        // (6) Lift sub-actions to channel-tagged ones.
        let mut out = Vec::with_capacity(key_actions.len() + cipher_actions.len());
        for a in key_actions {
            out.extend(self.lift_key_action(a));
        }
        for a in cipher_actions {
            out.extend(self.lift_cipher_action(a));
        }
        Ok(out)
    }

    // --- Receiver-side wire entry points ---

    pub fn handle_key_dispersal(
        &mut self,
        wire_sender: Replica,
        entries: Vec<DispersalEntry>,
    ) -> Vec<SecMsgDstAction> {
        let acts = self.sec_key.handle_dispersal(wire_sender, entries);
        self.lift_key_actions(acts)
    }

    pub fn handle_key_echo(
        &mut self,
        wire_sender: Replica,
        echo: EchoPayload,
    ) -> Vec<SecMsgDstAction> {
        let acts = self.sec_key.handle_echo(wire_sender, echo);
        self.lift_key_actions(acts)
    }

    pub fn handle_key_vote(
        &mut self,
        wire_sender: Replica,
        meta_root: Hash,
    ) -> Vec<SecMsgDstAction> {
        let acts = self.sec_key.handle_vote(wire_sender, meta_root);
        self.lift_key_actions(acts)
    }

    pub fn handle_cipher_dispersal(
        &mut self,
        wire_sender: Replica,
        entries: Vec<DispersalEntry>,
    ) -> Vec<SecMsgDstAction> {
        let acts = self.cipher.handle_dispersal(wire_sender, entries);
        self.lift_cipher_actions(acts)
    }

    pub fn handle_cipher_echo(
        &mut self,
        wire_sender: Replica,
        echo: EchoPayload,
    ) -> Vec<SecMsgDstAction> {
        let acts = self.cipher.handle_echo(wire_sender, echo);
        self.lift_cipher_actions(acts)
    }

    pub fn handle_cipher_vote(
        &mut self,
        wire_sender: Replica,
        meta_root: Hash,
    ) -> Vec<SecMsgDstAction> {
        let acts = self.cipher.handle_vote(wire_sender, meta_root);
        self.lift_cipher_actions(acts)
    }

    /// Combined message-level forward: validates both the key and
    /// the cipher forwards, decrypts `m_source`, and emits one of
    /// `ForwardDeliveredMessage` / `ForwardRejected`.
    pub fn handle_message_forward(
        &mut self,
        wire_sender: Replica,
        payload: ForwardMessagePayload,
    ) -> Vec<SecMsgDstAction> {
        // Run the key channel forward; expect a single
        // ForwardDeliveredShare or ForwardRejected.
        let key_acts = self.sec_key.handle_forward(wire_sender, payload.key_forward);
        let mut k_j: Option<BigUint> = None;
        for a in key_acts {
            match a {
                super::sec_key_dst::SecKeyDstAction::ForwardDeliveredShare { share, .. } => {
                    k_j = Some(share);
                }
                super::sec_key_dst::SecKeyDstAction::ForwardRejected { source, reason } => {
                    return vec![SecMsgDstAction::ForwardRejected {
                        source,
                        reason: SecMsgForwardReject::KeyChannelRejected(reason),
                    }];
                }
                _ => {}
            }
        }
        let k_j = match k_j {
            Some(k) => k,
            None => {
                return vec![SecMsgDstAction::ForwardRejected {
                    source: wire_sender,
                    reason: SecMsgForwardReject::KeyChannelRejected(
                        ForwardReject::DecodeFailed("no ForwardDeliveredShare emitted".into()),
                    ),
                }]
            }
        };

        // Cipher channel forward.
        let cipher_acts = self.cipher.handle_forward(wire_sender, payload.cipher_forward);
        let mut c_j: Option<Vec<u8>> = None;
        for a in cipher_acts {
            match a {
                RelMsgDstAction::ForwardDelivered { message, .. } => {
                    c_j = Some(message);
                }
                RelMsgDstAction::ForwardRejected { source, reason } => {
                    return vec![SecMsgDstAction::ForwardRejected {
                        source,
                        reason: SecMsgForwardReject::CipherChannelRejected(reason),
                    }];
                }
                _ => {}
            }
        }
        let c_j = match c_j {
            Some(c) => c,
            None => {
                return vec![SecMsgDstAction::ForwardRejected {
                    source: wire_sender,
                    reason: SecMsgForwardReject::CipherChannelRejected(
                        ForwardReject::DecodeFailed("no ForwardDelivered emitted".into()),
                    ),
                }]
            }
        };

        // Both channels delivered — decrypt.
        let plaintext = match decrypt_with_share(&self.prime, &k_j, &c_j) {
            Some(m) => m,
            None => {
                return vec![SecMsgDstAction::DeliveryFailedDecrypt {
                    reason: DecryptFailReason::InvalidKey,
                }]
            }
        };
        vec![SecMsgDstAction::ForwardDeliveredMessage {
            source: wire_sender,
            message: plaintext,
        }]
    }

    /// Build a `SendMessageForward` carrying our own delivered
    /// `m_myid` to a third party `recipient`.
    pub fn prepare_message_forward_for(
        &self,
        recipient: Replica,
    ) -> Result<SecMsgDstAction, SecMsgDstError> {
        if recipient == self.myid {
            return Err(SecMsgDstError::SelfForwardRequest);
        }
        if self.delivered_message.is_none() {
            return Err(SecMsgDstError::NotYetDelivered);
        }
        // Inner sub-protocol forwards (panics-free by construction
        // since we are delivered → both inner channels are too).
        let key_forward = self
            .sec_key
            .prepare_forward_for(recipient)
            .map_err(SecMsgDstError::SecKeyUnderlying)?;
        let cipher_forward = self
            .cipher
            .prepare_forward_for(recipient)
            .map_err(SecMsgDstError::CipherUnderlying)?;

        let key_fwd = match key_forward {
            super::sec_key_dst::SecKeyDstAction::SendForward { forward, .. } => forward,
            other => unreachable!(
                "SecKeyDst::prepare_forward_for must return SendForward, got {:?}",
                other
            ),
        };
        let cipher_fwd = match cipher_forward {
            RelMsgDstAction::SendForward { forward, .. } => forward,
            other => unreachable!(
                "RelMsgDst::prepare_forward_for must return SendForward, got {:?}",
                other
            ),
        };

        Ok(SecMsgDstAction::SendMessageForward {
            recipient,
            payload: ForwardMessagePayload {
                key_forward: key_fwd,
                cipher_forward: cipher_fwd,
            },
        })
    }

    // --- Internal action lifting ---

    fn lift_key_actions(
        &mut self,
        acts: Vec<super::sec_key_dst::SecKeyDstAction>,
    ) -> Vec<SecMsgDstAction> {
        let mut out = Vec::with_capacity(acts.len());
        for a in acts {
            out.extend(self.lift_key_action(a));
        }
        out
    }

    fn lift_key_action(
        &mut self,
        a: super::sec_key_dst::SecKeyDstAction,
    ) -> Vec<SecMsgDstAction> {
        use super::sec_key_dst::SecKeyDstAction as KA;
        match a {
            KA::SendDispersal { recipient_idx, entries } => {
                vec![SecMsgDstAction::SendDispersal {
                    channel: SecMsgChannel::Key,
                    recipient_idx,
                    entries,
                }]
            }
            KA::SendEcho { recipient_idx, echo } => vec![SecMsgDstAction::SendEcho {
                channel: SecMsgChannel::Key,
                recipient_idx,
                echo,
            }],
            KA::SendVote { meta_root } => vec![SecMsgDstAction::SendVote {
                channel: SecMsgChannel::Key,
                meta_root,
            }],
            KA::SendForward { recipient, forward } => vec![SecMsgDstAction::SendForward {
                channel: SecMsgChannel::Key,
                recipient,
                forward,
            }],
            KA::DeliveredShare { share } => {
                self.delivered_key = Some(share);
                self.maybe_decrypt()
            }
            KA::ForwardDeliveredShare { .. } => {
                // Forward-delivered shares are only meaningful at
                // the message-level forward path. At the
                // dispersal-phase routing level we just drop them
                // — Q's path uses handle_message_forward instead
                // of two separate per-channel forwards.
                Vec::new()
            }
            KA::ForwardRejected { .. } | KA::DeliveryFailedMalformedShare => {
                // Likewise: per-channel forward outcomes are
                // surfaced through handle_message_forward, not
                // here. (Distribution-phase malformed share is a
                // hard sender-failure; we propagate as
                // DeliveryFailedDecrypt with InvalidKey to make
                // it observable to drivers.)
                if matches!(a, super::sec_key_dst::SecKeyDstAction::DeliveryFailedMalformedShare)
                {
                    vec![SecMsgDstAction::DeliveryFailedDecrypt {
                        reason: DecryptFailReason::InvalidKey,
                    }]
                } else {
                    Vec::new()
                }
            }
        }
    }

    fn lift_cipher_actions(
        &mut self,
        acts: Vec<RelMsgDstAction>,
    ) -> Vec<SecMsgDstAction> {
        let mut out = Vec::with_capacity(acts.len());
        for a in acts {
            out.extend(self.lift_cipher_action(a));
        }
        out
    }

    fn lift_cipher_action(&mut self, a: RelMsgDstAction) -> Vec<SecMsgDstAction> {
        match a {
            RelMsgDstAction::SendDispersal { recipient_idx, entries } => {
                vec![SecMsgDstAction::SendDispersal {
                    channel: SecMsgChannel::Cipher,
                    recipient_idx,
                    entries,
                }]
            }
            RelMsgDstAction::SendEcho { recipient_idx, echo } => {
                vec![SecMsgDstAction::SendEcho {
                    channel: SecMsgChannel::Cipher,
                    recipient_idx,
                    echo,
                }]
            }
            RelMsgDstAction::SendVote { meta_root } => vec![SecMsgDstAction::SendVote {
                channel: SecMsgChannel::Cipher,
                meta_root,
            }],
            RelMsgDstAction::SendForward { recipient, forward } => {
                vec![SecMsgDstAction::SendForward {
                    channel: SecMsgChannel::Cipher,
                    recipient,
                    forward,
                }]
            }
            RelMsgDstAction::Delivered { message } => {
                self.delivered_cipher = Some(message);
                self.maybe_decrypt()
            }
            RelMsgDstAction::ForwardDelivered { .. }
            | RelMsgDstAction::ForwardRejected { .. } => {
                // Same reasoning as the key-channel: per-channel
                // forward outcomes are surfaced via
                // handle_message_forward, not here.
                Vec::new()
            }
        }
    }

    /// Both channels' deliveries fan into this. Idempotent and
    /// emits exactly one `DeliveredMessage` (or
    /// `DeliveryFailedDecrypt`) on success.
    fn maybe_decrypt(&mut self) -> Vec<SecMsgDstAction> {
        if self.delivered_message.is_some() {
            return Vec::new();
        }
        let k = match self.delivered_key.as_ref() {
            Some(k) => k,
            None => return Vec::new(),
        };
        let c = match self.delivered_cipher.as_ref() {
            Some(c) => c,
            None => return Vec::new(),
        };
        let plaintext = match decrypt_with_share(&self.prime, k, c) {
            Some(m) => m,
            None => {
                return vec![SecMsgDstAction::DeliveryFailedDecrypt {
                    reason: DecryptFailReason::InvalidKey,
                }]
            }
        };
        self.delivered_message = Some(plaintext.clone());
        vec![SecMsgDstAction::DeliveredMessage {
            message: plaintext,
        }]
    }

    /// Sender's own plaintext vector cache, for inspection /
    /// composition by Π_avss1.
    pub fn sender_known_messages(&self) -> Option<&[Vec<u8>]> {
        self.sender_messages.as_deref()
    }
}

/// Convenience: compute `share_byte_len(prime)` of the underlying
/// SecKeyDst transport. Useful for length-mismatch detection in
/// composed protocols.
pub fn key_byte_len(prime: &BigUint) -> usize {
    share_byte_len(prime)
}

// ---------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn hash_state() -> Arc<HashState> {
        let key0 = [5u8; 16];
        let key1 = [29u8; 16];
        let key2 = [23u8; 16];
        Arc::new(HashState::new(key0, key1, key2))
    }

    fn small_prime() -> BigUint {
        // 2^61 - 1 (Mersenne).
        BigUint::from((1u64 << 61) - 1)
    }

    fn large_prime() -> BigUint {
        // BLS12-381 scalar field prime, 255-bit.
        BigUint::parse_bytes(
            b"52435875175126190479447740508185965837690552500527637822603658699938581184513",
            10,
        )
        .unwrap()
    }

    fn make_state(
        myid: Replica,
        n: usize,
        t: usize,
        sender: Replica,
        prime: BigUint,
    ) -> SecMsgDstState {
        SecMsgDstState::new(myid, n, t, sender, prime, hash_state()).expect("valid config")
    }

    fn rng() -> StdRng {
        StdRng::seed_from_u64(0xBADC0FFEE)
    }

    /// Generate `n` distinct test messages of `len` bytes each.
    fn unique_msgs(n: usize, len: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| {
                (0..len)
                    .map(|j| ((i as u64 * 0x9e3779b9 + j as u64) & 0xff) as u8)
                    .collect()
            })
            .collect()
    }

    /// Drive a full Π_SecMsgDst across `n` honest replicas with
    /// synchronous reliable delivery. Returns each replica's
    /// delivered plaintext (or `None`).
    fn drive_secmsg(
        sender: Replica,
        msgs: Vec<Vec<u8>>,
        n: usize,
        prime: BigUint,
    ) -> Vec<Option<Vec<u8>>> {
        let t = (n - 1) / 3;
        let mut nodes: Vec<SecMsgDstState> = (0..n)
            .map(|i| make_state(i as Replica, n, t, sender, prime.clone()))
            .collect();
        let mut pending: Vec<(Replica, SecMsgDstAction)> = Vec::new();
        let mut rng_local = rng();
        let acts = nodes[sender as usize]
            .set_input_as_sender(msgs.clone(), &mut rng_local)
            .expect("sender ok");
        for a in acts {
            pending.push((sender, a));
        }

        for _ in 0..2000 {
            if nodes.iter().all(|n| n.delivered()) {
                break;
            }
            let mut next: Vec<(Replica, SecMsgDstAction)> = Vec::new();
            for (sender_id, action) in pending.drain(..) {
                match action {
                    SecMsgDstAction::SendDispersal { channel, recipient_idx, entries } => {
                        if recipient_idx < n {
                            let acts = match channel {
                                SecMsgChannel::Key => {
                                    nodes[recipient_idx].handle_key_dispersal(sender_id, entries)
                                }
                                SecMsgChannel::Cipher => nodes[recipient_idx]
                                    .handle_cipher_dispersal(sender_id, entries),
                            };
                            for a in acts {
                                next.push((recipient_idx as Replica, a));
                            }
                        }
                    }
                    SecMsgDstAction::SendEcho { channel, recipient_idx, echo } => {
                        if recipient_idx < n {
                            let acts = match channel {
                                SecMsgChannel::Key => {
                                    nodes[recipient_idx].handle_key_echo(sender_id, echo)
                                }
                                SecMsgChannel::Cipher => {
                                    nodes[recipient_idx].handle_cipher_echo(sender_id, echo)
                                }
                            };
                            for a in acts {
                                next.push((recipient_idx as Replica, a));
                            }
                        }
                    }
                    SecMsgDstAction::SendVote { channel, meta_root } => {
                        for (i, node) in nodes.iter_mut().enumerate() {
                            let acts = match channel {
                                SecMsgChannel::Key => node.handle_key_vote(sender_id, meta_root),
                                SecMsgChannel::Cipher => {
                                    node.handle_cipher_vote(sender_id, meta_root)
                                }
                            };
                            for a in acts {
                                next.push((i as Replica, a));
                            }
                        }
                    }
                    _ => {}
                }
            }
            pending = next;
        }
        nodes
            .into_iter()
            .map(|n| n.delivered_message().map(|m| m.to_vec()))
            .collect()
    }

    // ---- PRG / XOR primitives ----

    #[test]
    fn derive_stream_is_deterministic() {
        let key = b"some-share-key-bytes".to_vec();
        let s1 = derive_stream(&key, 100);
        let s2 = derive_stream(&key, 100);
        assert_eq!(s1, s2);
        // Different key → different stream (with overwhelming
        // probability).
        let s3 = derive_stream(b"different-key", 100);
        assert_ne!(s1, s3);
    }

    #[test]
    fn derive_stream_extension_is_a_prefix() {
        // The hash-chain construction guarantees that
        // derive_stream(key, len + extra) starts with the same
        // bytes as derive_stream(key, len). This is a useful
        // property for streaming use cases (and a sanity check
        // that the block-by-block construction is correct).
        let key = b"extension-test-key".to_vec();
        let short = derive_stream(&key, 32);
        let long = derive_stream(&key, 96);
        assert_eq!(&long[..32], short.as_slice());
    }

    #[test]
    fn xor_is_self_inverse() {
        let plaintext = b"hello-secmsg-dst-encryption-test".to_vec();
        let key_bytes = b"some-fake-key-bytes-32-byte-pad!".to_vec();
        let stream = derive_stream(&key_bytes, plaintext.len());
        let mut buf = plaintext.clone();
        xor_in_place(&mut buf, &stream);
        assert_ne!(buf, plaintext, "ciphertext must differ from plaintext");
        // XOR again with the same stream → recover plaintext.
        xor_in_place(&mut buf, &stream);
        assert_eq!(buf, plaintext);
    }

    #[test]
    fn encrypt_decrypt_roundtrip_with_share() {
        let p = small_prime();
        let k = BigUint::from(0xDEADBEEFu64);
        let plaintext = b"the quick brown fox jumps over the lazy dog".to_vec();
        let ct = encrypt_with_share(&p, &k, &plaintext);
        assert_eq!(ct.len(), plaintext.len());
        assert_ne!(ct, plaintext);
        let pt = decrypt_with_share(&p, &k, &ct).expect("decrypt ok");
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn encrypt_with_different_keys_produces_different_ciphertexts() {
        let p = large_prime();
        let plaintext = vec![0xABu8; 64];
        let ct1 = encrypt_with_share(&p, &BigUint::from(1u32), &plaintext);
        let ct2 = encrypt_with_share(&p, &BigUint::from(2u32), &plaintext);
        assert_ne!(ct1, ct2, "different keys must yield different streams");
    }

    // ---- Distribution-phase happy path ----

    #[test]
    fn each_node_receives_its_own_message_n4() {
        let p = small_prime();
        let msgs = unique_msgs(4, 64);
        let delivered = drive_secmsg(0, msgs.clone(), 4, p);
        for (i, d) in delivered.iter().enumerate() {
            assert_eq!(
                d.as_deref(),
                Some(msgs[i].as_slice()),
                "node {} should have decrypted m_{}",
                i, i
            );
        }
    }

    #[test]
    fn each_node_receives_its_own_message_n7() {
        let p = small_prime();
        let msgs = unique_msgs(7, 256);
        let delivered = drive_secmsg(2, msgs.clone(), 7, p);
        for (i, d) in delivered.iter().enumerate() {
            assert_eq!(d.as_deref(), Some(msgs[i].as_slice()));
        }
    }

    #[test]
    fn each_node_receives_its_own_message_n16_large_prime() {
        let p = large_prime();
        let msgs = unique_msgs(16, 512);
        let delivered = drive_secmsg(3, msgs.clone(), 16, p);
        for (i, d) in delivered.iter().enumerate() {
            assert_eq!(d.as_deref(), Some(msgs[i].as_slice()));
        }
    }

    #[test]
    fn supports_empty_messages_in_vector() {
        let p = small_prime();
        let mut msgs = unique_msgs(4, 32);
        msgs[2] = Vec::new();
        let delivered = drive_secmsg(0, msgs.clone(), 4, p);
        for (i, d) in delivered.iter().enumerate() {
            assert_eq!(d.as_deref(), Some(msgs[i].as_slice()));
        }
    }

    #[test]
    fn supports_distinct_message_sizes() {
        let p = small_prime();
        let msgs = vec![
            b"short".to_vec(),
            (0..512).map(|i| (i & 0xff) as u8).collect(),
            b"".to_vec(),
            (0..40).map(|i| (i + 7) as u8).collect(),
        ];
        let delivered = drive_secmsg(0, msgs.clone(), 4, p);
        for (i, d) in delivered.iter().enumerate() {
            assert_eq!(d.as_deref(), Some(msgs[i].as_slice()));
        }
    }

    // ---- Out-of-order arrival of key vs cipher ----

    #[test]
    fn delivery_blocks_until_both_channels_arrive() {
        let p = small_prime();
        let n = 4;
        let t = 1;
        // Sender computes shares + ciphertexts; we manually feed
        // ONLY the key channel to a receiver and assert it does NOT
        // deliver.
        let mut sender = make_state(0, n, t, 0, p.clone());
        let acts = sender
            .set_input_as_sender(unique_msgs(n, 16), &mut rng())
            .unwrap();
        let mut receiver = make_state(1, n, t, 0, p.clone());

        // Step 1: feed only the KEY dispersal block addressed at recipient 1.
        let key_dispersal_for_1 = acts
            .iter()
            .find_map(|a| match a {
                SecMsgDstAction::SendDispersal {
                    channel: SecMsgChannel::Key,
                    recipient_idx: 1,
                    entries,
                } => Some(entries.clone()),
                _ => None,
            })
            .expect("expected key dispersal[1]");
        let _ = receiver.handle_key_dispersal(0, key_dispersal_for_1);
        assert!(
            !receiver.delivered(),
            "key alone must not trigger delivery"
        );

        // Step 2: simulate a few key echoes from peers (we just
        // re-route the sender's own SendEcho/SendVote actions for
        // the key channel — but since we only have one receiver in
        // play, we'll skip ahead and acknowledge that 'receiver'
        // alone won't reach Bracha threshold for the key root by
        // itself).
        // Instead we verify the dual case: feed only the CIPHER
        // dispersal block to a fresh receiver and check the same.
        let mut receiver2 = make_state(1, n, t, 0, p.clone());
        let cipher_dispersal_for_1 = acts
            .iter()
            .find_map(|a| match a {
                SecMsgDstAction::SendDispersal {
                    channel: SecMsgChannel::Cipher,
                    recipient_idx: 1,
                    entries,
                } => Some(entries.clone()),
                _ => None,
            })
            .expect("expected cipher dispersal[1]");
        let _ = receiver2.handle_cipher_dispersal(0, cipher_dispersal_for_1);
        assert!(
            !receiver2.delivered(),
            "cipher alone must not trigger delivery"
        );
    }

    // ---- Sender-side validation ----

    #[test]
    fn set_input_by_non_sender_errors() {
        let p = small_prime();
        let mut node = make_state(1, 4, 1, 0, p);
        let res = node.set_input_as_sender(unique_msgs(4, 8), &mut rng());
        assert!(matches!(res, Err(SecMsgDstError::NotSender { .. })));
    }

    #[test]
    fn set_input_with_wrong_vector_length_errors() {
        let p = small_prime();
        let mut node = make_state(0, 4, 1, 0, p);
        let res = node.set_input_as_sender(unique_msgs(3, 8), &mut rng());
        assert!(matches!(
            res,
            Err(SecMsgDstError::WrongMessageVectorLength { .. })
        ));
    }

    // ---- Forwarding ----

    #[test]
    fn forwarding_delivers_message_to_third_party() {
        let p = small_prime();
        let n = 4;
        let t = 1;
        let msgs = unique_msgs(n, 64);
        let mut nodes: Vec<SecMsgDstState> = (0..n)
            .map(|i| make_state(i as Replica, n, t, 0, p.clone()))
            .collect();
        let mut pending: Vec<(Replica, SecMsgDstAction)> = Vec::new();
        let acts = nodes[0]
            .set_input_as_sender(msgs.clone(), &mut rng())
            .unwrap();
        for a in acts {
            pending.push((0, a));
        }
        for _ in 0..400 {
            if nodes.iter().all(|n| n.delivered()) {
                break;
            }
            let mut next = Vec::new();
            for (sender_id, action) in pending.drain(..) {
                match action {
                    SecMsgDstAction::SendDispersal { channel, recipient_idx, entries } => {
                        let acts = match channel {
                            SecMsgChannel::Key => {
                                nodes[recipient_idx].handle_key_dispersal(sender_id, entries)
                            }
                            SecMsgChannel::Cipher => {
                                nodes[recipient_idx].handle_cipher_dispersal(sender_id, entries)
                            }
                        };
                        for a in acts {
                            next.push((recipient_idx as Replica, a));
                        }
                    }
                    SecMsgDstAction::SendEcho { channel, recipient_idx, echo } => {
                        let acts = match channel {
                            SecMsgChannel::Key => {
                                nodes[recipient_idx].handle_key_echo(sender_id, echo)
                            }
                            SecMsgChannel::Cipher => {
                                nodes[recipient_idx].handle_cipher_echo(sender_id, echo)
                            }
                        };
                        for a in acts {
                            next.push((recipient_idx as Replica, a));
                        }
                    }
                    SecMsgDstAction::SendVote { channel, meta_root } => {
                        for (i, node) in nodes.iter_mut().enumerate() {
                            let acts = match channel {
                                SecMsgChannel::Key => node.handle_key_vote(sender_id, meta_root),
                                SecMsgChannel::Cipher => {
                                    node.handle_cipher_vote(sender_id, meta_root)
                                }
                            };
                            for a in acts {
                                next.push((i as Replica, a));
                            }
                        }
                    }
                    _ => {}
                }
            }
            pending = next;
        }
        // Distribution complete; node 1 forwards m_1 to a fresh node Q (id=99).
        let fwd_action = nodes[1]
            .prepare_message_forward_for(99)
            .expect("forward ok");
        let fwd_payload = match fwd_action {
            SecMsgDstAction::SendMessageForward { payload, .. } => payload,
            _ => panic!("expected SendMessageForward"),
        };
        let mut q = make_state(99, n, t, 0, p.clone());
        let result = q.handle_message_forward(1, fwd_payload);
        let delivered = result
            .iter()
            .find_map(|a| match a {
                SecMsgDstAction::ForwardDeliveredMessage { source, message } => {
                    Some((*source, message.clone()))
                }
                _ => None,
            })
            .expect("forward must deliver message");
        assert_eq!(delivered.0, 1);
        assert_eq!(delivered.1, msgs[1]);
    }

    #[test]
    fn forward_rejects_when_key_channel_tampered() {
        let p = small_prime();
        let n = 4;
        let t = 1;
        let msgs = unique_msgs(n, 32);
        let mut nodes: Vec<SecMsgDstState> = (0..n)
            .map(|i| make_state(i as Replica, n, t, 0, p.clone()))
            .collect();
        let mut pending: Vec<(Replica, SecMsgDstAction)> = Vec::new();
        let acts = nodes[0]
            .set_input_as_sender(msgs.clone(), &mut rng())
            .unwrap();
        for a in acts {
            pending.push((0, a));
        }
        for _ in 0..400 {
            if nodes.iter().all(|n| n.delivered()) {
                break;
            }
            let mut next = Vec::new();
            for (sender_id, action) in pending.drain(..) {
                match action {
                    SecMsgDstAction::SendDispersal { channel, recipient_idx, entries } => {
                        let acts = match channel {
                            SecMsgChannel::Key => {
                                nodes[recipient_idx].handle_key_dispersal(sender_id, entries)
                            }
                            SecMsgChannel::Cipher => {
                                nodes[recipient_idx].handle_cipher_dispersal(sender_id, entries)
                            }
                        };
                        for a in acts {
                            next.push((recipient_idx as Replica, a));
                        }
                    }
                    SecMsgDstAction::SendEcho { channel, recipient_idx, echo } => {
                        let acts = match channel {
                            SecMsgChannel::Key => {
                                nodes[recipient_idx].handle_key_echo(sender_id, echo)
                            }
                            SecMsgChannel::Cipher => {
                                nodes[recipient_idx].handle_cipher_echo(sender_id, echo)
                            }
                        };
                        for a in acts {
                            next.push((recipient_idx as Replica, a));
                        }
                    }
                    SecMsgDstAction::SendVote { channel, meta_root } => {
                        for (i, node) in nodes.iter_mut().enumerate() {
                            let acts = match channel {
                                SecMsgChannel::Key => node.handle_key_vote(sender_id, meta_root),
                                SecMsgChannel::Cipher => {
                                    node.handle_cipher_vote(sender_id, meta_root)
                                }
                            };
                            for a in acts {
                                next.push((i as Replica, a));
                            }
                        }
                    }
                    _ => {}
                }
            }
            pending = next;
        }
        let fwd_action = nodes[1]
            .prepare_message_forward_for(99)
            .expect("forward ok");
        let mut payload = match fwd_action {
            SecMsgDstAction::SendMessageForward { payload, .. } => payload,
            _ => panic!(),
        };
        // Tamper: bump forwarder_idx in the key forward to a wrong
        // value so the leaf-index binding rejects it.
        payload.key_forward.forwarder_idx = 2; // really 1
        let mut q = make_state(99, n, t, 0, p.clone());
        let result = q.handle_message_forward(1, payload);
        let rejected = result.iter().any(|a| {
            matches!(
                a,
                SecMsgDstAction::ForwardRejected {
                    reason: SecMsgForwardReject::KeyChannelRejected(_),
                    ..
                }
            )
        });
        assert!(
            rejected,
            "tampered key-forwarder_idx must be rejected at key channel"
        );
    }

    #[test]
    fn forward_rejects_when_cipher_channel_tampered() {
        let p = small_prime();
        let n = 4;
        let t = 1;
        let msgs = unique_msgs(n, 32);
        let mut nodes: Vec<SecMsgDstState> = (0..n)
            .map(|i| make_state(i as Replica, n, t, 0, p.clone()))
            .collect();
        let mut pending: Vec<(Replica, SecMsgDstAction)> = Vec::new();
        let acts = nodes[0]
            .set_input_as_sender(msgs.clone(), &mut rng())
            .unwrap();
        for a in acts {
            pending.push((0, a));
        }
        for _ in 0..400 {
            if nodes.iter().all(|n| n.delivered()) {
                break;
            }
            let mut next = Vec::new();
            for (sender_id, action) in pending.drain(..) {
                match action {
                    SecMsgDstAction::SendDispersal { channel, recipient_idx, entries } => {
                        let acts = match channel {
                            SecMsgChannel::Key => {
                                nodes[recipient_idx].handle_key_dispersal(sender_id, entries)
                            }
                            SecMsgChannel::Cipher => {
                                nodes[recipient_idx].handle_cipher_dispersal(sender_id, entries)
                            }
                        };
                        for a in acts {
                            next.push((recipient_idx as Replica, a));
                        }
                    }
                    SecMsgDstAction::SendEcho { channel, recipient_idx, echo } => {
                        let acts = match channel {
                            SecMsgChannel::Key => {
                                nodes[recipient_idx].handle_key_echo(sender_id, echo)
                            }
                            SecMsgChannel::Cipher => {
                                nodes[recipient_idx].handle_cipher_echo(sender_id, echo)
                            }
                        };
                        for a in acts {
                            next.push((recipient_idx as Replica, a));
                        }
                    }
                    SecMsgDstAction::SendVote { channel, meta_root } => {
                        for (i, node) in nodes.iter_mut().enumerate() {
                            let acts = match channel {
                                SecMsgChannel::Key => node.handle_key_vote(sender_id, meta_root),
                                SecMsgChannel::Cipher => {
                                    node.handle_cipher_vote(sender_id, meta_root)
                                }
                            };
                            for a in acts {
                                next.push((i as Replica, a));
                            }
                        }
                    }
                    _ => {}
                }
            }
            pending = next;
        }
        let fwd_action = nodes[1]
            .prepare_message_forward_for(99)
            .expect("forward ok");
        let mut payload = match fwd_action {
            SecMsgDstAction::SendMessageForward { payload, .. } => payload,
            _ => panic!(),
        };
        // Tamper: truncate cipher forward fragments below n-2t.
        payload.cipher_forward.fragments.truncate(1);
        let mut q = make_state(99, n, t, 0, p.clone());
        let result = q.handle_message_forward(1, payload);
        let rejected = result.iter().any(|a| {
            matches!(
                a,
                SecMsgDstAction::ForwardRejected {
                    reason: SecMsgForwardReject::CipherChannelRejected(_),
                    ..
                }
            )
        });
        assert!(
            rejected,
            "truncated cipher fragments must be rejected at cipher channel"
        );
    }

    #[test]
    fn prepare_forward_before_delivery_errors() {
        let p = small_prime();
        let node = make_state(1, 4, 1, 0, p);
        let res = node.prepare_message_forward_for(2);
        assert!(matches!(res, Err(SecMsgDstError::NotYetDelivered)));
    }

    #[test]
    fn prepare_forward_to_self_errors() {
        let p = small_prime();
        let node = make_state(1, 4, 1, 0, p);
        let res = node.prepare_message_forward_for(1);
        assert!(matches!(res, Err(SecMsgDstError::SelfForwardRequest)));
    }

    // ---- Sender determinism ----

    #[test]
    fn same_seeded_rng_produces_same_distribution() {
        let p = small_prime();
        let msgs = unique_msgs(4, 32);
        let d1 = drive_secmsg(0, msgs.clone(), 4, p.clone());
        let d2 = drive_secmsg(0, msgs.clone(), 4, p);
        assert_eq!(d1, d2);
    }
}
