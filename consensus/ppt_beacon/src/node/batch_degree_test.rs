//! R=1 batched degree checking for the PPTB binary-field path.
//!
//! The main batch shares one independent mask polynomial. Sealed reserve
//! coins keep their own masks and per-coin checks: opening the main batch
//! must not expose any relation involving a still sealed reserve coin.
//! SecMsg main challenges bind the encrypted input before h is computed.
//! Lite comparisons retain share paths. Separate SecMsg/public RBC voting
//! remains; no complete adaptive/QROM proof is claimed by this implementation.
use crypto::gf2::{Gf2Element, Gf2Profile};
use crypto::hash::{do_hash, Hash};
use types::{Replica, Round};
use types::beacon::{AvssPublicCommitMsg, AvssRecipientPayload, Val};
use super::{Context, context::PPT_COIN_RESERVE};

/// Root of the complete encrypted main input, fixed BEFORE challenge/response.
/// The private plaintext excludes h/theta, so this ordering has no cycle.
pub(crate) fn secmsg_input_root(round: Round, dealer: Replica, roots: &[Hash],
    key_cipher: (Hash, Hash), batch: usize, n: usize, f: usize,
    profile: Gf2Profile) -> Hash {
    let mut input = b"PPTB_SECMSG_BATCH_INPUT_v1::".to_vec();
    input.extend_from_slice(&round.to_be_bytes());
    for value in [dealer, batch, n, f, profile.w_p, profile.w_q, roots.len()] {
        input.extend_from_slice(&(value as u64).to_be_bytes());
    }
    input.extend_from_slice(&key_cipher.0);
    input.extend_from_slice(&key_cipher.1);
    for root in roots { input.extend_from_slice(root); }
    do_hash(&input)
}

/// One independently domain-separated coefficient per main input polynomial.
/// The full commitment and field/batch parameters are fixed before derivation.
pub(crate) fn challenges(round: Round, dealer: Replica, roots: &[Hash],
    batch: usize, n: usize, f: usize, profile: Gf2Profile,
    secmsg_root: Option<&Hash>) -> Vec<Gf2Element> {
    let mut input = b"PPTB_BATCH_DEGREE_R1_COMMIT_v1::".to_vec();
    input.extend_from_slice(&round.to_be_bytes());
    for value in [dealer, batch, n, f, profile.w_p as usize, profile.w_q as usize, roots.len()] {
        input.extend_from_slice(&(value as u64).to_be_bytes());
    }
    for root in roots { input.extend_from_slice(root); }
    let commitment = secmsg_root.copied().unwrap_or_else(|| do_hash(&input));
    (0..batch).map(|coin| {
        let domain: &[u8] = if secmsg_root.is_some() { b"PPTB_SECMSG_BATCH_COEFFICIENT_v1::" }
            else { b"PPTB_BATCH_DEGREE_R1_COEFFICIENT_v1::" };
        let mut query = domain.to_vec();
        query.extend_from_slice(&commitment);
        query.extend_from_slice(&(coin as u64).to_be_bytes());
        Gf2Element::from_random_bytes(profile, do_hash(&query))
    }).collect()
}

pub(crate) fn response(f_polys: &[Vec<Gf2Element>], mask: &[Gf2Element],
    theta: &[Gf2Element]) -> Vec<Val> {
    assert_eq!(f_polys.len(), theta.len());
    let mut h = mask.to_vec();
    for (polynomial, theta) in f_polys.iter().zip(theta) {
        assert_eq!(polynomial.len(), h.len());
        for (coefficient, secret) in h.iter_mut().zip(polynomial) {
            *coefficient = coefficient.add(&theta.mul_small(secret));
        }
    }
    h.iter().map(|value| *value.as_bytes()).collect()
}

pub(crate) fn public_shape(public: &AvssPublicCommitMsg, batch: usize,
    n: usize, f: usize, profile: Option<Gf2Profile>) -> bool {
    if batch == 0 || public.origin >= n
        || public.root_vec.len() != batch.saturating_add(PPT_COIN_RESERVE) {
        return false;
    }
    let count = if profile.is_some() { 1 + PPT_COIN_RESERVE }
        else { batch + PPT_COIN_RESERVE };
    public.degree_test_coeffs.len() == count && public.degree_test_coeffs.iter().all(|h| {
        h.len() == f + 1 && profile.map(|profile| {
            h.iter().all(|value| Gf2Element::from_bytes(profile, *value).is_ok())
        }).unwrap_or(true)
    })
}

/// Check normalized (per-coin mask view) data. Merkle input authentication
/// remains the caller's responsibility. Only complete main/reserve groups
/// may be checked; a fragment of the main batch cannot satisfy this check.
pub(crate) fn verify_values(public: &AvssPublicCommitMsg, secrets: &[Val], masks: &[Val],
    offset: usize, batch: usize, source: Replica, n: usize, f: usize,
    profile: Gf2Profile, secmsg_root: Option<&Hash>) -> bool {
    if source >= n || secrets.len() != masks.len()
        || !public_shape(public, batch, n, f, Some(profile)) { return false; }
    let total = batch + PPT_COIN_RESERVE;
    let main = offset == 0 && (secrets.len() == batch || secrets.len() == total);
    let reserve = (main && secrets.len() == total)
        || (offset == batch && secrets.len() == PPT_COIN_RESERVE);
    if !main && !reserve { return false; }
    let base = match Gf2Profile::new(profile.w_p, profile.w_p) { Ok(p) => p, Err(_) => return false };
    let verifier = match super::shamir::gf2_two_field::Gf2TwoFieldDealer::new(profile, f + 1, n) {
        Ok(v) => v, Err(_) => return false,
    };
    let x = super::shamir::gf2_two_field::small_field_point(profile, source + 1);
    if main {
        if masks[..batch].iter().any(|mask| mask != &masks[0]) { return false; }
        let mut combination = match Gf2Element::from_bytes(profile, masks[0]) {
            Ok(value) => value, Err(_) => return false,
        };
        let theta = challenges(public.round, public.origin, &public.root_vec, batch, n, f, profile, secmsg_root);
        for (secret, theta) in secrets[..batch].iter().zip(&theta) {
            if Gf2Element::from_bytes(base, *secret).is_err() { return false; }
            let secret = match Gf2Element::from_bytes(profile, *secret) { Ok(v) => v, Err(_) => return false };
            combination = combination.add(&theta.mul_small(&secret));
        }
        let coefficients: Vec<_> = public.degree_test_coeffs[0].iter()
            .map(|v| Gf2Element::from_bytes(profile, *v).expect("public_shape checked encoding"))
            .collect();
        if super::shamir::gf2_two_field::eval_poly_horner_small_x(profile, &coefficients, x)
            != combination { return false; }
    }
    if reserve {
        // Keep the PR11 sealed-coin derivation and reveal schedule unchanged.
        let theta = Context::theta_from_commitment_gf2(public.round, public.origin, &public.root_vec, profile);
        let start = if main { batch } else { 0 };
        for coin in 0..PPT_COIN_RESERVE {
            let secret_bytes = secrets[start + coin];
            if Gf2Element::from_bytes(base, secret_bytes).is_err() { return false; }
            let secret = match Gf2Element::from_bytes(profile, secret_bytes) { Ok(v) => v, Err(_) => return false };
            let mask = match Gf2Element::from_bytes(profile, masks[start + coin]) { Ok(v) => v, Err(_) => return false };
            let coefficients: Vec<_> = public.degree_test_coeffs[1 + coin].iter()
                .map(|v| Gf2Element::from_bytes(profile, *v).expect("public_shape checked encoding"))
                .collect();
            if !verifier.verify_share(source + 1, &secret, &mask, &coefficients, &theta) { return false; }
        }
    }
    true
}

/// Internal state keeps a per-coin mask view for existing reconstruction and
/// reserve bookkeeping. The main mask occurs ONLY ONCE in transport bytes.
pub(crate) fn encode_payload(payload: &AvssRecipientPayload, profile: Option<Gf2Profile>,
    batch: usize, offset: usize) -> Option<Vec<u8>> {
    let mut wire = payload.clone();
    if profile.is_some() && offset == 0 {
        if batch == 0 || (wire.secrets.len() != batch && wire.secrets.len() != batch + PPT_COIN_RESERVE)
            || wire.mask_shares.len() != wire.secrets.len()
            || wire.mask_shares[..batch].iter().any(|v| v != &wire.mask_shares[0]) { return None; }
        let mut masks = vec![wire.mask_shares[0]];
        masks.extend_from_slice(&wire.mask_shares[batch..]);
        wire.mask_shares = masks;
    }
    Some(wire.serialize_bytes())
}

pub(crate) fn decode_payload(bytes: &[u8], profile: Option<Gf2Profile>,
    batch: usize, offset: usize) -> Option<AvssRecipientPayload> {
    let mut payload = AvssRecipientPayload::deserialize_bytes(bytes)?;
    if payload.serialize_bytes() != bytes { return None; }
    if profile.is_some() {
        let len = payload.secrets.len();
        if offset == 0 {
            if batch == 0 || (len != batch && len != batch + PPT_COIN_RESERVE)
                || payload.mask_shares.len() != 1 + len - batch { return None; }
            let mut masks = vec![payload.mask_shares[0]; batch];
            masks.extend_from_slice(&payload.mask_shares[1..]);
            payload.mask_shares = masks;
        } else if offset != batch || len != PPT_COIN_RESERVE || payload.mask_shares.len() != len {
            return None;
        }
    }
    Some(payload)
}

impl Context {
    pub(crate) fn batch_input_root(&self, round: Round, dealer: Replica) -> Option<Hash> {
        self.avss_public_bundles.get(&(round, dealer)).and_then(|bundle| bundle.challenge_root)
    }

    /// A dealer-authenticated TCP message is insufficient. Proofless inputs
    /// come only from a complete SecMsg delivery under the agreed key/cipher roots.
    pub(crate) fn has_secmsg_batch_delivery(&self, round: Round, dealer: Replica) -> bool {
        let roots = match self.avss_public_bundles.get(&(round, dealer)).and_then(|b| b.secmsg_roots) {
            Some(roots) => roots, None => return false,
        };
        let bytes = match self.avss_beacon_bytes.get(&(round, dealer)) { Some(b) => b, None => return false };
        self.avss_secmsg_state.get(&(round, dealer)).map(|state| {
            state.commitment_roots() == Some(roots) && state.delivered_message() == Some(bytes.as_slice())
        }).unwrap_or(false)
    }
}
