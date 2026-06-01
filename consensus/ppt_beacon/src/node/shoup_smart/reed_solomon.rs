//! Reed-Solomon (n, n-2t) erasure coding for the Shoup-Smart 2024
//! AVSS protocol.
//!
//! Reference: Victor Shoup and Nigel P. Smart, "Lightweight Asynchronous
//! Verifiable Secret Sharing with Optimal Resilience", Journal of
//! Cryptology 37(3):27, 2024 (DOI 10.1007/s00145-024-09505-6).
//! Specifically Section 3.2.2 ("CompactBroadcast") which says:
//!
//! > "we need an (n, n-2t) erasure code, which has the following
//! >  properties: a message m can be efficiently encoded as a
//! >  vector of n fragments (f_1, ..., f_n) in such a way that m
//! >  can be efficiently reconstructed (decoded) from any subset
//! >  of n-2t fragments. An (n, n-2t)-Reed-Solomon code can be
//! >  used for this purpose...the size of each fragment will be
//! >  about |m| / (n-2t)."
//!
//! This module exposes:
//!
//! * `RsEncoder` — encodes a byte payload into `n` fragments. Any
//!   `n - 2t` fragments are sufficient for decoding.
//! * `RsDecoder` — given an indexed multiset of fragments, recovers
//!   the original payload. Fails with `InsufficientFragments` if
//!   fewer than `n - 2t` fragments are provided, with `LengthMismatch`
//!   if fragment shapes disagree (Byzantine-supplied bad fragment
//!   shapes are caught here), or with `Underlying` for any reed-solomon
//!   library-level error.
//!
//! ## Threading and `Send + Sync`
//!
//! Both `RsEncoder` and `RsDecoder` are `Clone + Send + Sync`, so they
//! may be moved into `tokio::task::spawn_blocking` closures without
//! external lifetime gymnastics. The underlying `reed-solomon-erasure`
//! crate's `ReedSolomon` is also `Send + Sync`.
//!
//! ## Wire-fragment format
//!
//! `Fragment` is a thin newtype wrapper around `Vec<u8>` of length
//! `shard_len = ceil(|payload| / (n - 2t))`. The encoder also
//! prepends a fixed 4-byte length prefix to the payload before
//! splitting (so that the original message length is recoverable
//! during decoding even when zero padding has been applied to make
//! `payload.len()` a multiple of `n - 2t`). This length prefix
//! reduces the maximum payload size to `2^32 - 5 ≈ 4 GiB`, which
//! is far above any practical AVSS share batch.
//!
//! ## Determinism
//!
//! Reed-Solomon over `GF(2^8)` is deterministic; the same input
//! always produces the same fragment vector, regardless of which
//! node calls `encode`. This is required by Shoup-Smart Sec 4.1 so
//! that the Merkle tree root computed by an honest receiver during
//! reconstruction is byte-identical to the one the dealer originally
//! committed to.

use std::fmt;
use std::sync::Arc;

use reed_solomon_erasure::{galois_8::ReedSolomon, Error as RsError};
use serde::{Deserialize, Serialize};

/// Maximum payload size = 2^32 - 5 bytes (4 GiB minus the length
/// prefix). Anything larger panics in `encode`.
const MAX_PAYLOAD_LEN: usize = (u32::MAX as usize) - 5;

/// Fixed length-prefix size used to recover the original payload
/// length after fragment-level zero padding. Stored big-endian as
/// `u32`.
const LENGTH_PREFIX_BYTES: usize = 4;

/// One Reed-Solomon fragment of fixed `shard_len` bytes. `Vec<u8>`
/// internally; we expose a typed wrapper so the rest of the
/// Shoup-Smart pipeline can construct strongly-typed Merkle leaves
/// (`hash(fragment.bytes())`) without confusing fragments with raw
/// data slices.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Fragment {
    bytes: Vec<u8>,
}

impl Fragment {
    /// Construct from an owned byte vector.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Read-only view of the wire bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Take ownership of the underlying byte vector.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Length of this fragment in bytes (every fragment from the
    /// same `RsEncoder` has the same length).
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// True if `bytes.is_empty()`.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Errors returned by the Shoup-Smart Reed-Solomon encoder/decoder.
#[derive(Debug)]
pub enum RsCodingError {
    /// Caller asked for `n` and `t` that violate the Shoup-Smart
    /// optimal-resilience invariant `t < n / 3`. Returned only by
    /// `RsEncoder::new` / `RsDecoder::new`.
    InvalidThreshold { n: usize, t: usize },
    /// `payload.len() > MAX_PAYLOAD_LEN`. Returned only by `encode`.
    PayloadTooLarge { len: usize },
    /// Fewer than `n - 2t` fragments were supplied to `decode`.
    InsufficientFragments {
        provided: usize,
        required: usize,
    },
    /// One of the supplied fragments did not have the expected
    /// `shard_len`. Catches a Byzantine sender that injects a
    /// truncated fragment.
    LengthMismatch {
        index: usize,
        expected: usize,
        actual: usize,
    },
    /// A supplied `(index, fragment)` pair carried `index >= n`.
    IndexOutOfRange { index: usize, n: usize },
    /// The recovered length-prefix is impossible (greater than the
    /// total decoded buffer). Indicates fragment corruption that
    /// passed the Reed-Solomon redundancy check by chance — we
    /// reject rather than return a truncated payload.
    LengthPrefixCorrupt { recovered: u64, buffer_len: usize },
    /// Underlying `reed-solomon-erasure` library failure (ought to
    /// be unreachable on the happy path, but we propagate it instead
    /// of panicking).
    Underlying(RsError),
}

impl fmt::Display for RsCodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RsCodingError::InvalidThreshold { n, t } => {
                write!(f, "invalid (n,t) = ({}, {}) for optimal-resilience RS code (need t < n/3)", n, t)
            }
            RsCodingError::PayloadTooLarge { len } => {
                write!(f, "payload too large: {} bytes (max {})", len, MAX_PAYLOAD_LEN)
            }
            RsCodingError::InsufficientFragments { provided, required } => {
                write!(f, "insufficient fragments for decode: provided {}, required {}", provided, required)
            }
            RsCodingError::LengthMismatch { index, expected, actual } => {
                write!(f, "fragment {} has wrong length {} (expected {})", index, actual, expected)
            }
            RsCodingError::IndexOutOfRange { index, n } => {
                write!(f, "fragment index {} out of range (n={})", index, n)
            }
            RsCodingError::LengthPrefixCorrupt { recovered, buffer_len } => {
                write!(f, "decoded length prefix {} exceeds buffer length {}", recovered, buffer_len)
            }
            RsCodingError::Underlying(e) => {
                write!(f, "reed-solomon library error: {:?}", e)
            }
        }
    }
}

impl std::error::Error for RsCodingError {}

/// Reed-Solomon `(n, n-2t)` encoder.
///
/// Constructed once per `(n, t)` configuration. Cheap to clone
/// (the underlying `ReedSolomon` lookup tables are wrapped in
/// `Arc` so cloning shares them).
#[derive(Clone)]
pub struct RsEncoder {
    n: usize,
    t: usize,
    /// `n - 2t`: the number of "data" shards.
    data_shards: usize,
    /// `2 * t`: the number of "parity" shards. Total shards =
    /// `data_shards + parity_shards = n - 2t + 2t = n`.
    parity_shards: usize,
    rs: Arc<ReedSolomon>,
}

impl fmt::Debug for RsEncoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsEncoder")
            .field("n", &self.n)
            .field("t", &self.t)
            .field("data_shards", &self.data_shards)
            .field("parity_shards", &self.parity_shards)
            .finish()
    }
}

impl RsEncoder {
    /// Construct an `(n, n-2t)` Reed-Solomon encoder.
    ///
    /// Requires `t < n / 3` (optimal resilience), `t > 0`, and
    /// `n >= 4`. The latter is the minimum useful case for AVSS
    /// (`t = 1`).
    pub fn new(n: usize, t: usize) -> Result<Self, RsCodingError> {
        if t == 0 || 3 * t >= n || n < 4 {
            return Err(RsCodingError::InvalidThreshold { n, t });
        }
        let data_shards = n - 2 * t;
        let parity_shards = 2 * t;
        let rs = ReedSolomon::new(data_shards, parity_shards)
            .map_err(RsCodingError::Underlying)?;
        Ok(Self {
            n,
            t,
            data_shards,
            parity_shards,
            rs: Arc::new(rs),
        })
    }

    pub fn n(&self) -> usize { self.n }
    pub fn t(&self) -> usize { self.t }
    pub fn data_shards(&self) -> usize { self.data_shards }
    pub fn parity_shards(&self) -> usize { self.parity_shards }

    /// Per-fragment byte length for a payload of `payload_len` bytes
    /// (after the 4-byte length prefix is added).
    pub fn shard_len_for_payload(&self, payload_len: usize) -> usize {
        let total = LENGTH_PREFIX_BYTES + payload_len;
        // ceil(total / data_shards), but we also guarantee shard_len
        // >= 1 even for an empty payload.
        let len = (total + self.data_shards - 1) / self.data_shards;
        len.max(1)
    }

    /// Encode `payload` into exactly `n` fragments in canonical
    /// order (i.e. fragment i corresponds to the encoder's i-th
    /// shard). Any `n - 2t` of these fragments are sufficient to
    /// recover the original payload.
    ///
    /// The encoding is deterministic: identical input bytes
    /// always produce identical output fragment vectors.
    pub fn encode(&self, payload: &[u8]) -> Result<Vec<Fragment>, RsCodingError> {
        if payload.len() > MAX_PAYLOAD_LEN {
            return Err(RsCodingError::PayloadTooLarge { len: payload.len() });
        }

        let shard_len = self.shard_len_for_payload(payload.len());
        let total_padded = shard_len * self.data_shards;
        debug_assert!(total_padded >= LENGTH_PREFIX_BYTES + payload.len());

        // (1) length-prefix + payload + zero-pad to total_padded.
        let mut buf = Vec::with_capacity(total_padded);
        buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(payload);
        buf.resize(total_padded, 0u8);

        // (2) split buf into data_shards shards of size shard_len.
        let mut shards: Vec<Vec<u8>> = Vec::with_capacity(self.data_shards + self.parity_shards);
        for i in 0..self.data_shards {
            let start = i * shard_len;
            let end = start + shard_len;
            shards.push(buf[start..end].to_vec());
        }
        for _ in 0..self.parity_shards {
            shards.push(vec![0u8; shard_len]);
        }
        debug_assert_eq!(shards.len(), self.n);

        // (3) compute parity shards in-place.
        self.rs.encode(&mut shards).map_err(RsCodingError::Underlying)?;

        // (4) wrap each shard in `Fragment`.
        Ok(shards.into_iter().map(Fragment::from_bytes).collect())
    }
}

/// Reed-Solomon `(n, n-2t)` decoder.
///
/// Cheap to clone (shares an `Arc<ReedSolomon>`).
#[derive(Clone)]
pub struct RsDecoder {
    n: usize,
    t: usize,
    data_shards: usize,
    parity_shards: usize,
    rs: Arc<ReedSolomon>,
}

impl fmt::Debug for RsDecoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsDecoder")
            .field("n", &self.n)
            .field("t", &self.t)
            .field("data_shards", &self.data_shards)
            .field("parity_shards", &self.parity_shards)
            .finish()
    }
}

impl RsDecoder {
    /// Construct a decoder for the same `(n, t)` configuration as
    /// the matching `RsEncoder`.
    pub fn new(n: usize, t: usize) -> Result<Self, RsCodingError> {
        if t == 0 || 3 * t >= n || n < 4 {
            return Err(RsCodingError::InvalidThreshold { n, t });
        }
        let data_shards = n - 2 * t;
        let parity_shards = 2 * t;
        let rs = ReedSolomon::new(data_shards, parity_shards)
            .map_err(RsCodingError::Underlying)?;
        Ok(Self {
            n,
            t,
            data_shards,
            parity_shards,
            rs: Arc::new(rs),
        })
    }

    pub fn n(&self) -> usize { self.n }
    pub fn t(&self) -> usize { self.t }
    /// `n - 2t`: the minimum number of fragments required to decode.
    pub fn min_fragments_required(&self) -> usize { self.data_shards }

    /// Decode the original payload from a multiset of indexed
    /// fragments.
    ///
    /// `fragments` is an iterable of `(index, Fragment)` pairs where
    /// `index in [0, n)` corresponds to the canonical shard index
    /// returned by `RsEncoder::encode`. Duplicate indices are
    /// allowed but only the first occurrence per index is honoured;
    /// later duplicates are silently dropped (this matches Bracha-
    /// style protocols where late ECHOes for the same shard are
    /// idempotent).
    ///
    /// Requires at least `n - 2t` *distinct* indices and that all
    /// supplied fragments have the same `shard_len`. On success
    /// returns the original payload bytes (length-prefix stripped).
    pub fn decode<I>(&self, fragments: I) -> Result<Vec<u8>, RsCodingError>
    where
        I: IntoIterator<Item = (usize, Fragment)>,
    {
        // (1) sort and de-dup fragments by index.
        let mut indexed: Vec<Option<Vec<u8>>> = vec![None; self.n];
        let mut shard_len: Option<usize> = None;
        let mut distinct = 0usize;
        for (idx, frag) in fragments.into_iter() {
            if idx >= self.n {
                return Err(RsCodingError::IndexOutOfRange { index: idx, n: self.n });
            }
            // First-seen wins; later duplicates are dropped.
            if indexed[idx].is_some() {
                continue;
            }
            // Lock fragment length on first fragment.
            match shard_len {
                None => shard_len = Some(frag.len()),
                Some(expected) if frag.len() != expected => {
                    return Err(RsCodingError::LengthMismatch {
                        index: idx,
                        expected,
                        actual: frag.len(),
                    });
                }
                _ => {}
            }
            indexed[idx] = Some(frag.into_bytes());
            distinct += 1;
        }

        if distinct < self.data_shards {
            return Err(RsCodingError::InsufficientFragments {
                provided: distinct,
                required: self.data_shards,
            });
        }

        // (2) reconstruct missing shards in-place.
        self.rs
            .reconstruct(&mut indexed)
            .map_err(RsCodingError::Underlying)?;

        // (3) concatenate the data shards (indices 0..data_shards)
        // back into the prefixed payload buffer.
        let shard_len = shard_len.expect("shard_len locked above when distinct > 0");
        let mut buf = Vec::with_capacity(shard_len * self.data_shards);
        for i in 0..self.data_shards {
            let shard = indexed[i]
                .as_ref()
                .expect("reconstruct fills missing data shards");
            if shard.len() != shard_len {
                return Err(RsCodingError::LengthMismatch {
                    index: i,
                    expected: shard_len,
                    actual: shard.len(),
                });
            }
            buf.extend_from_slice(shard);
        }

        // (4) strip the 4-byte length prefix and validate.
        if buf.len() < LENGTH_PREFIX_BYTES {
            return Err(RsCodingError::LengthPrefixCorrupt {
                recovered: 0,
                buffer_len: buf.len(),
            });
        }
        let len_bytes: [u8; 4] = buf[..LENGTH_PREFIX_BYTES]
            .try_into()
            .expect("buf[..4] is 4 bytes by construction");
        let payload_len = u32::from_be_bytes(len_bytes) as usize;
        if LENGTH_PREFIX_BYTES + payload_len > buf.len() {
            return Err(RsCodingError::LengthPrefixCorrupt {
                recovered: payload_len as u64,
                buffer_len: buf.len(),
            });
        }
        let mut payload = buf;
        payload.drain(..LENGTH_PREFIX_BYTES);
        payload.truncate(payload_len);
        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(n: usize, t: usize) -> RsEncoder {
        RsEncoder::new(n, t).expect("valid (n,t) config")
    }
    fn dec(n: usize, t: usize) -> RsDecoder {
        RsDecoder::new(n, t).expect("valid (n,t) config")
    }

    // ---- Construction sanity ----

    #[test]
    fn rejects_invalid_thresholds() {
        // t = 0 (no fault tolerance) is rejected.
        assert!(matches!(
            RsEncoder::new(4, 0),
            Err(RsCodingError::InvalidThreshold { .. })
        ));
        // t > (n-1)/3 violates optimal resilience.
        assert!(matches!(
            RsEncoder::new(4, 2),
            Err(RsCodingError::InvalidThreshold { .. })
        ));
        // n < 4 is too small for AVSS (t < n/3 has no positive
        // integer solution).
        assert!(matches!(
            RsEncoder::new(3, 1),
            Err(RsCodingError::InvalidThreshold { .. })
        ));
        // Boundary case: n = 3t + 1 just barely valid.
        assert!(RsEncoder::new(4, 1).is_ok());
        assert!(RsEncoder::new(7, 2).is_ok());
        assert!(RsEncoder::new(16, 5).is_ok());
        assert!(RsEncoder::new(64, 21).is_ok());
    }

    // ---- Round-trip correctness ----

    #[test]
    fn roundtrip_random_payloads_at_n4_t1() {
        // (4, 2) shape: 2 data shards, 2 parity shards. Need any
        // 2 fragments to recover.
        let e = enc(4, 1);
        let d = dec(4, 1);
        assert_eq!(e.data_shards(), 2);
        assert_eq!(e.parity_shards(), 2);

        for &payload_len in &[1usize, 2, 7, 64, 1023, 65537] {
            let payload: Vec<u8> = (0..payload_len)
                .map(|i| (((i as u64).wrapping_mul(0x9e3779b9u64) ^ payload_len as u64) & 0xff) as u8)
                .collect();
            let frags = e.encode(&payload).expect("encode ok");
            assert_eq!(frags.len(), 4);

            // All four fragments → decode succeeds.
            let mut all = Vec::new();
            for (i, f) in frags.iter().cloned().enumerate() {
                all.push((i, f));
            }
            assert_eq!(d.decode(all).expect("full decode ok"), payload);
        }
    }

    #[test]
    fn roundtrip_with_exactly_min_fragments() {
        // n = 16, t = 5. data_shards = 6, parity_shards = 10.
        // Decoding needs exactly 6 fragments, any of the 16.
        let e = enc(16, 5);
        let d = dec(16, 5);
        let payload = b"Shoup-Smart 2024 AVSS Reed-Solomon roundtrip with min fragments".to_vec();
        let frags = e.encode(&payload).expect("encode ok");

        // Take 6 fragments: half data half parity, deliberately skipping
        // around the index space.
        let picks: Vec<_> = vec![1, 4, 7, 9, 11, 13]
            .into_iter()
            .map(|i| (i, frags[i].clone()))
            .collect();
        assert_eq!(picks.len(), 6);
        assert_eq!(d.decode(picks).expect("min-fragment decode ok"), payload);
    }

    #[test]
    fn roundtrip_with_only_parity_fragments() {
        // n = 16, t = 5. parity_shards = 10 ≥ data_shards = 6.
        // So if we hand the decoder ONLY parity fragments, it can
        // still recover the data.
        let e = enc(16, 5);
        let d = dec(16, 5);
        let payload: Vec<u8> = (0..1024).map(|i| i as u8).collect();
        let frags = e.encode(&payload).expect("encode ok");

        // Take only parity shards (indices data_shards..n = 6..16).
        let picks: Vec<_> = (6..16)
            .map(|i| (i, frags[i].clone()))
            .take(6) // need 6, take 6
            .collect();
        assert_eq!(d.decode(picks).expect("parity-only decode ok"), payload);
    }

    // ---- Failure modes ----

    #[test]
    fn fails_with_insufficient_fragments() {
        let e = enc(4, 1);
        let d = dec(4, 1);
        let payload = b"insufficient_fragments_test".to_vec();
        let frags = e.encode(&payload).expect("encode ok");

        // Only 1 fragment when we need 2 → InsufficientFragments.
        let picks = vec![(0usize, frags[0].clone())];
        let err = d.decode(picks).expect_err("should fail with 1 fragment");
        assert!(matches!(err, RsCodingError::InsufficientFragments { .. }));
    }

    #[test]
    fn fails_with_truncated_fragment() {
        let e = enc(7, 2);
        let d = dec(7, 2);
        let payload = b"abcdefghijklmnopqrstuvwxyz0123456789!@#".to_vec();
        let frags = e.encode(&payload).expect("encode ok");

        let mut bad_frags = frags.clone();
        // Truncate fragment 0 by one byte → caught as LengthMismatch
        // before the RS library is invoked.
        let mut bad = bad_frags[0].as_bytes().to_vec();
        bad.pop();
        bad_frags[0] = Fragment::from_bytes(bad);

        let picks: Vec<_> = (0..3)
            .map(|i| (i, bad_frags[i].clone()))
            .collect();
        let err = d.decode(picks).expect_err("should fail on length mismatch");
        assert!(matches!(err, RsCodingError::LengthMismatch { .. }));
    }

    #[test]
    fn fails_with_index_out_of_range() {
        let e = enc(4, 1);
        let d = dec(4, 1);
        let frags = e.encode(b"x").expect("encode ok");
        // index = 4 ≥ n is caught explicitly.
        let bad_picks = vec![(0, frags[0].clone()), (4, frags[1].clone())];
        let err = d.decode(bad_picks).expect_err("index 4 out of range");
        assert!(matches!(err, RsCodingError::IndexOutOfRange { .. }));
    }

    #[test]
    fn duplicate_indices_are_idempotent() {
        // The decoder uses first-seen-wins on duplicate indices.
        // This matches Bracha-style protocols where late ECHO
        // copies are dropped without error.
        let e = enc(4, 1);
        let d = dec(4, 1);
        let payload = b"duplicate_index_test".to_vec();
        let frags = e.encode(&payload).expect("encode ok");

        // Provide fragment 0 twice + fragment 1 once. Distinct count = 2,
        // matches data_shards.
        let picks = vec![
            (0usize, frags[0].clone()),
            (0usize, frags[0].clone()), // duplicate, dropped
            (1usize, frags[1].clone()),
        ];
        assert_eq!(d.decode(picks).expect("dup-tolerant decode ok"), payload);
    }

    #[test]
    fn empty_payload_is_supported() {
        // The Shoup-Smart protocol may need to disperse a zero-length
        // message in degenerate edge cases (e.g. a placeholder
        // dealer who has nothing to share). The encoder must not
        // panic on |payload| = 0.
        let e = enc(4, 1);
        let d = dec(4, 1);
        let frags = e.encode(b"").expect("encode empty ok");
        assert_eq!(frags.len(), 4);
        let picks: Vec<_> = (0..2).map(|i| (i, frags[i].clone())).collect();
        let recovered = d.decode(picks).expect("decode empty ok");
        assert_eq!(recovered, b"");
    }

    #[test]
    fn deterministic_encoding() {
        // Property required by Shoup-Smart Sec 4.1: encoding is a
        // deterministic function of the input. Two honest dealers
        // who happen to share the same payload would produce
        // byte-identical fragment vectors and Merkle commitments.
        let e1 = enc(16, 5);
        let e2 = enc(16, 5);
        let payload: Vec<u8> = (0..512).map(|i| (i * 7) as u8).collect();
        let frags1 = e1.encode(&payload).expect("encode ok");
        let frags2 = e2.encode(&payload).expect("encode ok");
        assert_eq!(frags1, frags2, "RS encoding must be deterministic");
    }

    #[test]
    fn shard_len_matches_paper_bound() {
        // Sec 3.2.2: "the size of each fragment will be about
        // |m| / (n-2t)." We additionally add a 4-byte length prefix
        // before splitting, so the bound should be
        // ceil((4 + |m|) / (n-2t)).
        let e = enc(16, 5); // n-2t = 6
        for &payload_len in &[1usize, 6, 7, 12, 60, 600] {
            let total = 4 + payload_len;
            let expected = (total + 5) / 6; // ceil(total / 6)
            let got = e.shard_len_for_payload(payload_len);
            assert_eq!(got, expected.max(1), "len mismatch for |m|={}", payload_len);
        }
    }

    #[test]
    fn large_payload_roundtrip() {
        // Test with a payload size representative of an AVSS
        // n=16 batch=500 single-recipient share (~32 KB).
        let e = enc(16, 5);
        let d = dec(16, 5);
        let mut payload = Vec::with_capacity(32 * 1024);
        for i in 0u32..32 * 1024 {
            payload.push(((i.wrapping_mul(0x9e3779b9u32)) & 0xff) as u8);
        }
        let frags = e.encode(&payload).expect("encode ok");
        // Take any 6 fragments.
        let picks: Vec<_> = (10..16).map(|i| (i, frags[i].clone())).collect();
        assert_eq!(d.decode(picks).expect("32K decode ok"), payload);
    }

    #[test]
    fn n16_t5_sec4_communication_bound() {
        // Sanity check: for the parameter set we'll actually use in
        // the PPT-AVSS pipeline (n=16, t=5, batch=500 shares of 32B),
        // each fragment is ~ 32 KB / (16 - 10) = ~5.4 KB instead of
        // the previous ~32 KB single-recipient payload — a 6×
        // saving per recipient (matching Sec 4.1.2's
        // O(|m|/(n-2t)) per-fragment bound).
        let e = enc(16, 5);
        let avss_payload_len = 500 * 64; // 500 shares × 64 bytes/share
        let shard_len = e.shard_len_for_payload(avss_payload_len);
        let total_per_recipient_old = avss_payload_len; // pre-Sec-4
        let total_per_recipient_new = shard_len; // post-Sec-4
        let saving = total_per_recipient_old as f64 / total_per_recipient_new as f64;
        // Should be very close to (n-2t) = 6, modulo small length-
        // prefix and rounding overhead.
        assert!(
            saving > 5.0 && saving < 6.5,
            "expected ~6× per-recipient saving for n=16,t=5,batch=500, got {:.2}× ({} vs {})",
            saving, total_per_recipient_old, total_per_recipient_new
        );
    }
}
