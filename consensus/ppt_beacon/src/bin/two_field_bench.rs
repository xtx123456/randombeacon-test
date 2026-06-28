//! Standalone microbenchmark for the PPT two-field optimization.
//!
//! This binary isolates the **core PPT two-field arithmetic** (dealer
//! sample + h(x) compute + verifier degree test + Lagrange recovery +
//! super-invertible randomness extraction + wire-size encoding) from
//! the rest of the consensus stack (networking, ACS, audit, …) so you
//! can directly compare BigUint vs GF(2^w_p)/GF(2^w_q) profiles
//! without having to spin up a full distributed beacon.
//!
//! Usage
//! -----
//!
//! ```text
//!   # Defaults: n=16, f=5, t=6, batch=1000.
//!   cargo run --release --bin two_field_bench
//!
//!   # Override via env vars:
//!   N=64 BATCH=2000 cargo run --release --bin two_field_bench
//!
//!   # Run only a specific profile list (comma-separated):
//!   PROFILES='BigUint,GF2(64,256),GF2(32,256)' \
//!     cargo run --release --bin two_field_bench
//! ```
//!
//! Reported columns
//! ----------------
//!
//! | Column             | Meaning                                              |
//! |--------------------|------------------------------------------------------|
//! | `dealer.sample`    | f-poly + g-poly sampling + per-recipient eval        |
//! | `dealer.h`         | h(x) = g(x) - θ·f(x) computation                    |
//! | `verify`           | one recipient's verify_share for the whole batch     |
//! | `lagrange`         | recover f(0) from t shares, one dealer per call      |
//! | `superinv`         | SuperInvExtractor::extract over decided set          |
//! | `wire_b/rcpt`      | bincode-serialised `AvssRecipientPayload` byte count |
//!
//! All time columns are **per coin per call** (μs). The wire column is
//! **total bytes** for one recipient's `AvssRecipientPayload` carrying
//! all `batch_size` coins; divide by `batch_size` to get per-coin
//! bytes.

use std::env;
use std::time::Instant;

use num_bigint::{BigUint, RandBigInt};

use crypto::gf2::{Gf2Element, Gf2Profile};

use ppt_beacon::node::shamir::gf2_two_field::{
    lagrange_recover_at_zero, Gf2SuperInvExtractor, Gf2TwoFieldDealer,
};
use ppt_beacon::node::shamir::two_field::{BatchExtractor, SuperInvExtractor, TwoFieldDealer};

/// Parsed profile from the `PROFILES=` env var. `BigUint` means the
/// legacy 50-bit-secret / 256-bit-mask prime-field path; `Gf2(p, q)`
/// means the new tower-field path.
#[derive(Clone, Copy, Debug)]
enum ProfileSpec {
    BigUint,
    Gf2(Gf2Profile),
}

impl ProfileSpec {
    fn label(&self) -> String {
        match self {
            Self::BigUint => "BigUint(p~50, q~256)".to_string(),
            Self::Gf2(p) => format!("GF2({:>3},{:>3})", p.w_p, p.w_q),
        }
    }
}

fn parse_profiles(env_value: Option<String>) -> Vec<ProfileSpec> {
    if let Some(s) = env_value {
        return s
            .split(',')
            .map(|t| t.trim())
            .filter(|t| !t.is_empty())
            .filter_map(|tok| {
                if tok.eq_ignore_ascii_case("BigUint") {
                    return Some(ProfileSpec::BigUint);
                }
                match tok.parse::<Gf2Profile>() {
                    Ok(p) => Some(ProfileSpec::Gf2(p)),
                    Err(e) => {
                        eprintln!("skipping '{}': {}", tok, e);
                        None
                    }
                }
            })
            .collect();
    }
    // Default sweep covering all the cases that actually matter:
    //   * BigUint baseline (the historical default)
    //   * Single-field GF(2^w) variants matching BigUint widths
    //   * Tower variants with progressively narrower small field
    let mut out = vec![ProfileSpec::BigUint];
    for &(p, q) in &[
        (64usize, 64usize),
        (128, 128),
        (8, 64),
        (16, 64),
        (32, 128),
        (32, 256),
        (64, 128),
        (64, 256),
        (128, 256),
        (8, 256),
    ] {
        if let Ok(prof) = Gf2Profile::new(p, q) {
            out.push(ProfileSpec::Gf2(prof));
        }
    }
    out
}

fn main() {
    let n: usize = env::var("N")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(16);
    let f: usize = env::var("F")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or((n - 1) / 3);
    let t: usize = f + 1;
    let batch: usize = env::var("BATCH")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1000);

    let profiles = parse_profiles(env::var("PROFILES").ok());

    println!("================================================================");
    println!("PPT two-field microbenchmark");
    println!("================================================================");
    println!("n         = {} recipients", n);
    println!("f         = {} Byzantine tolerance", f);
    println!("t = f+1   = {} reconstruction threshold", t);
    println!("batch     = {} coins per dealer per round", batch);
    println!("profiles  = {}", profiles.len());
    println!();
    println!(
        "{:<22}  {:>14}  {:>12}  {:>12}  {:>12}  {:>12}  {:>12}",
        "profile",
        "dealer.sample",
        "dealer.h",
        "verify",
        "lagrange",
        "superinv",
        "wire_B/rcpt",
    );
    println!(
        "{:<22}  {:>14}  {:>12}  {:>12}  {:>12}  {:>12}  {:>12}",
        "",
        "(μs/coin)",
        "(μs/coin)",
        "(μs/coin)",
        "(μs/coin)",
        "(μs/coin)",
        "(bytes)",
    );
    println!("{}", "-".repeat(110));

    for prof in profiles {
        match prof {
            ProfileSpec::BigUint => bench_biguint(n, f, t, batch),
            ProfileSpec::Gf2(p) => {
                // Skip if n exceeds the small field's distinct-point
                // capacity. The Gf2TwoFieldDealer constructor would
                // reject; do it here for a clean message.
                let max_n = if p.w_p >= 63 {
                    usize::MAX
                } else {
                    (1usize << p.w_p) - 1
                };
                if n > max_n {
                    println!(
                        "{:<22}  -- skipped: n={} > 2^w_p - 1 = {} (need w_p > {} bits)",
                        prof.label(),
                        n,
                        max_n,
                        (n + 1).next_power_of_two().trailing_zeros()
                    );
                    continue;
                }
                bench_gf2(p, n, f, t, batch, &prof.label());
            }
        }
    }

    println!();
    println!("Notes:");
    println!(
        "  * `dealer.sample` covers: sample f (small-field), sample g (large-field),"
    );
    println!(
        "    evaluate both at all n=`{}` recipient points (large field for f also). \
         Total work per dealer per round is `dealer.sample * batch`.",
        n,
    );
    println!("  * `dealer.h` covers: compute h(x) = g(x) - θ·f(x) at given θ.");
    println!(
        "  * `verify`: one honest recipient's full verify_share + cross-binding"
    );
    println!(
        "    check (BigUint mode) for the whole batch — divide by batch to get per-coin."
    );
    println!(
        "  * `lagrange`: recover f(0) from t={} shares, one dealer's worth per call.",
        t,
    );
    println!(
        "  * `superinv`: SuperInvExtractor over all n decided dealers; produces"
    );
    println!("    m-f = {} extracted beacon values per coin column.", n - f);
    println!(
        "  * `wire_B/rcpt`: bincode-serialised `AvssRecipientPayload` byte count"
    );
    println!(
        "    for ONE recipient. Multiply by n to get the dealer's per-round wire"
    );
    println!(
        "    traffic in lite transport. GF(2^w) values reflect commit 7 wire"
    );
    println!("    compaction (f_large_shares = None).");
}

// =============================================================================
// BigUint baseline
// =============================================================================

fn bench_biguint(n: usize, f: usize, t: usize, batch: usize) {
    let p = BigUint::from(685373784908497u64); // ~50-bit (the production secret_domain)
    let q = BigUint::parse_bytes(
        b"57896044618658097711785492504343953926634992332820282019728792003956564819949",
        10,
    )
    .unwrap(); // 256-bit nonce/mask domain
    let dealer = TwoFieldDealer::new(p.clone(), q.clone(), t, n);
    let mut rng = rand::thread_rng();

    // ----- Dealer sample -----
    let start = Instant::now();
    let mut sampled = Vec::with_capacity(batch);
    for _ in 0..batch {
        let secret = rng.gen_biguint_range(&BigUint::from(0u32), &p);
        sampled.push(dealer.sample_shares(secret));
    }
    let t_sample_ns = start.elapsed().as_nanos();

    // ----- Dealer compute_h -----
    let theta = rng.gen_biguint_range(&BigUint::from(0u32), &q);
    let start = Instant::now();
    let mut hs = Vec::with_capacity(batch);
    for s in &sampled {
        hs.push(dealer.compute_degree_test_poly_pub(&s.f_poly, &s.g_poly, &theta));
    }
    let t_h_ns = start.elapsed().as_nanos();

    // ----- Verifier: one recipient verifies the whole batch -----
    let rcpt = 1usize; // node 1 (1-based)
    let start = Instant::now();
    let mut accepted = 0usize;
    for (coin, s) in sampled.iter().enumerate() {
        let f_large = &s.f_large_shares[rcpt - 1].1;
        let g = &s.mask_shares[rcpt - 1].1;
        if dealer.verify_share(rcpt, f_large, g, &hs[coin], &theta) {
            // Cross-binding: share == f_large mod p
            let share = &s.secret_shares[rcpt - 1].1;
            if share == &(f_large % &p) {
                accepted += 1;
            }
        }
    }
    let t_verify_ns = start.elapsed().as_nanos();
    assert_eq!(accepted, batch, "BigUint verifier should accept honest");

    // ----- Lagrange recover from t shares per coin -----
    let eval_points: Vec<usize> = (1..=t).collect();
    let extractor = BatchExtractor::new(eval_points.clone(), p.clone());
    let start = Instant::now();
    let mut recovered = Vec::with_capacity(batch);
    for s in &sampled {
        let shares: Vec<BigUint> =
            (0..t).map(|i| s.secret_shares[i].1.clone()).collect();
        recovered.push(extractor.recover_one(&shares));
    }
    let t_lagrange_ns = start.elapsed().as_nanos();

    // ----- SuperInvExtractor over decided dealers -----
    let m = n; // assume entire honest set decided
    let alpha_points: Vec<usize> = (1..=m).collect();
    let superinv = SuperInvExtractor::new(alpha_points, m - f, p.clone());
    // We need one "decided dealer secret column" per coin. The honest
    // path runs `superinv.extract` once per coin with the m-vector of
    // recovered f_d(0). We reuse the same vector batch times to time.
    let inputs: Vec<BigUint> = (0..m).map(|_| recovered[0].clone()).collect();
    let start = Instant::now();
    for _ in 0..batch {
        let _ = superinv.extract(&inputs);
    }
    let t_superinv_ns = start.elapsed().as_nanos();

    // ----- Wire size for one recipient's AvssRecipientPayload -----
    use types::beacon::{AvssRecipientPayload, Val};
    let rcpt_idx = rcpt - 1;
    let secrets: Vec<Val> = sampled
        .iter()
        .map(|s| pad32_be(&s.secret_shares[rcpt_idx].1))
        .collect();
    let nonces: Vec<Val> = (0..batch).map(|_| [0u8; 32]).collect();
    let mask_shares: Vec<Val> = sampled
        .iter()
        .map(|s| pad32_be(&s.mask_shares[rcpt_idx].1))
        .collect();
    let f_large_shares: Vec<Val> = sampled
        .iter()
        .map(|s| pad32_be(&s.f_large_shares[rcpt_idx].1))
        .collect();
    let payload = AvssRecipientPayload::new(secrets, nonces, mask_shares, Some(f_large_shares), Vec::new());
    let wire_bytes = payload.serialize_bytes().len();

    print_row(
        "BigUint(p~50, q~256)",
        t_sample_ns,
        t_h_ns,
        t_verify_ns,
        t_lagrange_ns,
        t_superinv_ns,
        wire_bytes,
        batch,
    );
}

// =============================================================================
// GF(2^w) variant
// =============================================================================

fn bench_gf2(profile: Gf2Profile, n: usize, f: usize, t: usize, batch: usize, label: &str) {
    let dealer = Gf2TwoFieldDealer::new(profile, t, n)
        .unwrap_or_else(|e| panic!("invalid (profile, t, n): {}", e));
    let mut rng = rand::thread_rng();

    // ----- Dealer sample -----
    let start = Instant::now();
    let mut sampled = Vec::with_capacity(batch);
    for _ in 0..batch {
        let small_len = profile.small_byte_len();
        let mut bytes = vec![0u8; small_len];
        use rand::Rng;
        rng.fill(&mut bytes[..]);
        let secret = Gf2Element::lift_small(profile, &bytes);
        sampled.push(dealer.sample_shares(secret));
    }
    let t_sample_ns = start.elapsed().as_nanos();

    // ----- Dealer compute_h -----
    let theta = {
        let mut buf = [0u8; 32];
        use rand::Rng;
        rng.fill(&mut buf[..]);
        Gf2Element::from_random_bytes(profile, buf)
    };
    let start = Instant::now();
    let mut hs = Vec::with_capacity(batch);
    for s in &sampled {
        hs.push(dealer.compute_degree_test_poly(&s.f_poly, &s.g_poly, &theta));
    }
    let t_h_ns = start.elapsed().as_nanos();

    // ----- Verifier: one recipient verifies the whole batch -----
    let rcpt = 1usize;
    let start = Instant::now();
    let mut accepted = 0usize;
    for (coin, s) in sampled.iter().enumerate() {
        let f_large = &s.f_large_shares[rcpt - 1].1;
        let g = &s.mask_shares[rcpt - 1].1;
        if dealer.verify_share(rcpt, f_large, g, &hs[coin], &theta) {
            // GF(2^w) cross-binding is tautological (commit 7) — skip.
            accepted += 1;
        }
    }
    let t_verify_ns = start.elapsed().as_nanos();
    assert_eq!(accepted, batch, "GF2 verifier should accept honest");

    // ----- Lagrange recover from t shares per coin -----
    let start = Instant::now();
    let mut recovered = Vec::with_capacity(batch);
    for s in &sampled {
        let points: Vec<(usize, Gf2Element)> =
            s.secret_shares.iter().take(t).copied().collect();
        recovered.push(lagrange_recover_at_zero(profile, &points));
    }
    let t_lagrange_ns = start.elapsed().as_nanos();

    // ----- Gf2SuperInvExtractor over decided dealers -----
    let m = n;
    let alpha_points: Vec<usize> = (1..=m).collect();
    let superinv = Gf2SuperInvExtractor::new(profile, alpha_points, m - f);
    let inputs: Vec<Gf2Element> = (0..m).map(|_| recovered[0]).collect();
    let start = Instant::now();
    for _ in 0..batch {
        let _ = superinv.extract(&inputs);
    }
    let t_superinv_ns = start.elapsed().as_nanos();

    // ----- Wire size for one recipient's AvssRecipientPayload -----
    use types::beacon::{AvssRecipientPayload, Val};
    let rcpt_idx = rcpt - 1;
    let secrets: Vec<Val> = sampled
        .iter()
        .map(|s| *s.secret_shares[rcpt_idx].1.as_bytes())
        .collect();
    let nonces: Vec<Val> = (0..batch).map(|_| [0u8; 32]).collect();
    let mask_shares: Vec<Val> = sampled
        .iter()
        .map(|s| *s.mask_shares[rcpt_idx].1.as_bytes())
        .collect();
    // Commit 7: GF(2^w) ships f_large_shares = None.
    let payload =
        AvssRecipientPayload::new(secrets, nonces, mask_shares, None, Vec::new());
    let wire_bytes = payload.serialize_bytes().len();

    print_row(
        label,
        t_sample_ns,
        t_h_ns,
        t_verify_ns,
        t_lagrange_ns,
        t_superinv_ns,
        wire_bytes,
        batch,
    );
}

// =============================================================================
// Helpers
// =============================================================================

fn pad32_be(value: &BigUint) -> [u8; 32] {
    let mut bytes = value.to_bytes_be();
    if bytes.len() > 32 {
        panic!("BigUint exceeds 32 bytes — refusing to truncate");
    }
    let mut out = vec![0u8; 32 - bytes.len()];
    out.append(&mut bytes);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

fn print_row(
    label: &str,
    t_sample_ns: u128,
    t_h_ns: u128,
    t_verify_ns: u128,
    t_lagrange_ns: u128,
    t_superinv_ns: u128,
    wire_bytes: usize,
    batch: usize,
) {
    let to_us_per_coin = |ns: u128| (ns as f64) / 1000.0 / (batch as f64);
    println!(
        "{:<22}  {:>14.3}  {:>12.3}  {:>12.3}  {:>12.3}  {:>12.3}  {:>12}",
        label,
        to_us_per_coin(t_sample_ns),
        to_us_per_coin(t_h_ns),
        to_us_per_coin(t_verify_ns),
        to_us_per_coin(t_lagrange_ns),
        to_us_per_coin(t_superinv_ns),
        wire_bytes,
    );
}
