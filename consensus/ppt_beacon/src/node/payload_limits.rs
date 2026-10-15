//! Protocol-sized bounds, checked before accepting data that can be replayed.
//! Bincode uses fixed-width vector lengths; a Merkle proof has two vectors.

pub(crate) fn plaintext(coins: usize, n: usize, binary: bool, proofless: bool,
    shared_mask: bool) -> Option<usize> {
    if n == 0 || coins == 0 { return None; }
    let depth = (usize::BITS - (n - 1).leading_zeros()) as usize;
    let proof = 80usize.checked_add(33usize.checked_mul(depth)?)?;
    let mask_count = if binary && shared_mask { 1 } else { coins };
    let values = coins.checked_mul(if binary { 2 } else { 3 })?.checked_add(mask_count)?;
    let header = if binary { 33usize } else { 41usize };
    header.checked_add(32usize.checked_mul(values)?)?
        .checked_add(if proofless { 0 } else { coins.checked_mul(proof)? })
}

pub(crate) fn fragment(message_bytes: usize, n: usize, f: usize) -> Option<usize> {
    let k = n.checked_sub(f.checked_mul(2)?)?;
    if k == 0 { return None; }
    Some(message_bytes.checked_add(4)?.checked_add(k - 1)? / k)
}

pub(crate) fn public_bundle(batch: usize, n: usize, binary: bool) -> Option<usize> {
    let roots = batch.checked_add(super::context::PPT_COIN_RESERVE)?;
    let responses = if binary { 1 + super::context::PPT_COIN_RESERVE } else { roots };
    // n bounds f+1. The fixed fields/options take less than 1024 bytes.
    1024usize.checked_add(roots.checked_mul(32)?)?
        .checked_add(responses.checked_mul(8usize.checked_add(n.checked_mul(32)?)?)?)
}

