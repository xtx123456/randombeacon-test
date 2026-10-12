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
//!   # Run only a specific profile list. The list is split at
//!   # TOP-LEVEL separators only, so the comma inside `GF2(32,256)`
//!   # is NOT a separator. `,` `;` and newlines all work:
//!   PROFILES='BigUint,GF2(64,256),GF2(32,256)' \
//!     cargo run --release --bin two_field_bench
//!   PROFILES='GF2(32,256); GF2(8,64)' cargo run --release --bin two_field_bench
//! ```
//!
//! A bare `64,256` (no parentheses) is *two* top-level tokens and is
//! rejected with a descriptive message — write `GF2(64,256)`.
//!
//! What is and is not measured
//! ---------------------------
//!
//! Every row runs in one process, from one build, with identical
//! `n`, `f` and `batch`. Within a row:
//!
//! * `dealer.sample` / `dealer.h` / `verify` / `superinv.extract`
//!   are steady-state per-coin costs; the one-off table builds they
//!   depend on (`superinv.build`, `lagrange.build`) are reported
//!   **separately** and are *not* folded into them.
//! * `lagrange.uncached` rebuilds the `O(t²)` Lagrange basis on every
//!   single recovery. `lagrange.cached` amortizes one basis build
//!   across the whole batch. Both numbers are printed so the
//!   precomputation is never hidden on one side only.
//! * The BigUint path has *always* been amortized (`BatchExtractor`
//!   holds the basis), so its "uncached" column is blank by
//!   construction — the GF2 uncached column is the pre-change GF2
//!   behaviour, not a BigUint-equivalent workload. Comparing
//!   `BigUint lagrange.cached` against `GF2 lagrange.uncached` would
//!   be comparing different amounts of precomputation and is wrong.
//!
//! Entropy caveat
//! --------------
//!
//! A "coin" is one secret, and the secret lives in the **small**
//! field. A `GF2(8,64)` coin therefore carries 8 bits of output
//! entropy while a `GF2(128,128)` coin carries 128. Per-coin times
//! across rows with different `w_p` are *not* the same amount of
//! randomness; the `out_bits` column states the width and the
//! `μs/128b` column renormalizes `dealer.sample` to a common 128-bit
//! output budget for the rows where that comparison is meaningful.
//!
//! Security-level caveat
//! ---------------------
//!
//! `GF2(64,64)` and `GF2(128,128)` are **same-field arithmetic
//! baselines**, not same-security-level protocol baselines. The PPT
//! degree test wants the challenge domain `q > 2^(128+n)`; a 128-bit
//! `w_q` does not satisfy that. Use those rows to price the
//! arithmetic, not to claim a protocol-level comparison.

use std::env;
use std::hint::black_box;
use std::time::Instant;

use num_bigint::{BigUint, RandBigInt};

use crypto::gf2::{Gf2Element, Gf2Profile};

use ppt_beacon::node::shamir::gf2_two_field::{
    check_point_set, lagrange_recover_at_zero, Gf2LagrangeBasis, Gf2LagrangeCache,
    Gf2SuperInvExtractor, Gf2TwoFieldDealer,
};
use ppt_beacon::node::shamir::two_field::{BatchExtractor, SuperInvExtractor, TwoFieldDealer};

/// Parsed profile from the `PROFILES=` env var. `BigUint` means the
/// legacy 50-bit-secret / 256-bit-mask prime-field path; `Gf2(p, q)`
/// means the new tower-field path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProfileSpec {
    BigUint,
    Gf2(Gf2Profile),
}

impl ProfileSpec {
    fn label(&self) -> String {
        match self {
            Self::BigUint => "BigUint(p~50,q~256)".to_string(),
            Self::Gf2(p) => format!("GF2({:>3},{:>3})", p.w_p, p.w_q),
        }
    }

    /// Bits of entropy in ONE recovered secret. The secret lives in
    /// the small field, so this is `w_p` — not `w_q`, and not the
    /// wire width.
    fn out_bits(&self) -> usize {
        match self {
            // floor(log2(685373784908497)) = 49.
            Self::BigUint => 49,
            Self::Gf2(p) => p.w_p,
        }
    }
}

/// Split a profile list at top-level separators only.
///
/// `GF2(32,256)` contains a comma that belongs to the *spec*, not to
/// the list, so a naive `split(',')` shreds it into `GF2(32` and
/// `256)`. Tracking bracket depth keeps nested commas intact.
/// `,` `;` and any whitespace are all accepted as separators at
/// depth 0, which makes multi-line `PROFILES` blocks work too.
fn split_top_level(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut depth: usize = 0;
    for ch in s.chars() {
        match ch {
            '(' | '[' => {
                depth += 1;
                cur.push(ch);
            }
            ')' | ']' => {
                depth = depth.saturating_sub(1);
                cur.push(ch);
            }
            ',' | ';' if depth == 0 => {
                out.push(std::mem::take(&mut cur));
            }
            c if c.is_whitespace() && depth == 0 => {
                out.push(std::mem::take(&mut cur));
            }
            _ => cur.push(ch),
        }
    }
    out.push(cur);
    out.into_iter()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect()
}

/// Parse one top-level token into a `ProfileSpec`.
fn parse_profile_token(tok: &str) -> Result<ProfileSpec, String> {
    if tok.eq_ignore_ascii_case("BigUint") {
        return Ok(ProfileSpec::BigUint);
    }
    tok.parse::<Gf2Profile>()
        .map(ProfileSpec::Gf2)
        .map_err(|e| {
            format!(
                "{} (write tower specs with parentheses, e.g. GF2(32,256))",
                e
            )
        })
}

/// The ten GF(2^w) configurations this round is required to exercise,
/// plus the two same-field arithmetic baselines that head the list.
const DEFAULT_GF2_PROFILES: [(usize, usize); 10] = [
    // Same-field arithmetic baselines (see the security-level caveat).
    (64, 64),
    (128, 128),
    // Two-field towers.
    (8, 64),
    (16, 64),
    (32, 128),
    (32, 256),
    (64, 128),
    (64, 256),
    (128, 256),
    (8, 256),
];

fn parse_profiles(env_value: Option<String>) -> Vec<ProfileSpec> {
    if let Some(s) = env_value {
        let mut out = Vec::new();
        for tok in split_top_level(&s) {
            match parse_profile_token(&tok) {
                Ok(p) => out.push(p),
                Err(e) => eprintln!("skipping '{}': {}", tok, e),
            }
        }
        return out;
    }
    let mut out = vec![ProfileSpec::BigUint];
    for &(p, q) in DEFAULT_GF2_PROFILES.iter() {
        match Gf2Profile::new(p, q) {
            Ok(prof) => out.push(ProfileSpec::Gf2(prof)),
            // An unsupported profile must be visible, never silently
            // swapped for a different field.
            Err(e) => eprintln!("default profile GF2({},{}) unavailable: {}", p, q, e),
        }
    }
    out
}

/// One row of measurements. All `*_ns` fields are raw totals; the
/// printers do the per-coin division so the same row can appear in
/// several tables without re-measuring.
struct BenchRow {
    label: String,
    out_bits: usize,
    batch: usize,

    t_sample_ns: u128,
    t_h_ns: u128,
    t_verify_ns: u128,

    /// One-off super-invertible matrix construction.
    t_superinv_build_ns: u128,
    /// `batch` extractions reusing that one matrix.
    t_superinv_ns: u128,

    /// `batch` recoveries, each rebuilding the Lagrange basis.
    /// `None` for BigUint, whose API has no uncached mode.
    t_lagrange_uncached_ns: Option<u128>,
    /// One-off Lagrange basis construction for a single point set.
    t_lagrange_build_ns: u128,
    /// `batch` recoveries reusing a cached basis (includes the one
    /// cache miss that builds it).
    t_lagrange_cached_ns: u128,
    cache_hits: u64,
    cache_misses: u64,

    /// Cost of one `mul` / `mul_small` with a base-field right
    /// operand. `None` for BigUint (no subfield fast path exists).
    arith: Option<ArithRow>,

    /// Serialized `AvssRecipientPayload` bytes for ONE recipient.
    /// Shares only — see the wire caveat in the notes.
    wire_bytes: usize,
}

struct ArithRow {
    ops: usize,
    t_mul_ns: u128,
    t_mul_small_ns: u128,
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
    println!(
        "build     = {} profile, one process, identical n/f/batch for every row",
        if cfg!(debug_assertions) {
            "debug (NOT a valid performance baseline)"
        } else {
            "release"
        }
    );
    println!();

    let mut rows: Vec<BenchRow> = Vec::new();
    for prof in &profiles {
        match prof {
            ProfileSpec::BigUint => rows.push(bench_biguint(n, f, t, batch, prof)),
            ProfileSpec::Gf2(p) => match Gf2TwoFieldDealer::new(*p, t, n) {
                Ok(dealer) => rows.push(bench_gf2(*p, dealer, n, f, t, batch, prof)),
                Err(e) => {
                    // Explicit rejection, never a silent field swap.
                    println!("{:<20}  -- rejected: {}", prof.label(), e);
                }
            },
        }
    }

    print_stage_table(&rows);
    println!();
    print_reconstruction_table(&rows);
    println!();
    print_arith_table(&rows);
    println!();
    report_capacity_rejections(t);
    println!();
    print_notes(n, f, t);
}

// =============================================================================
// Tables
// =============================================================================

fn print_stage_table(rows: &[BenchRow]) {
    println!("Table 1 — protocol stage cost (steady state, μs per coin)");
    println!(
        "{:<20}  {:>8}  {:>13}  {:>10}  {:>10}  {:>10}  {:>14}  {:>11}",
        "profile",
        "out_bits",
        "dealer.sample",
        "dealer.h",
        "verify",
        "superinv",
        "superinv.build",
        "wire_B/rcpt",
    );
    println!(
        "{:<20}  {:>8}  {:>13}  {:>10}  {:>10}  {:>10}  {:>14}  {:>11}",
        "", "(bits)", "(μs/coin)", "(μs/coin)", "(μs/coin)", "(μs/coin)", "(μs once)", "(bytes)",
    );
    println!("{}", "-".repeat(110));
    for r in rows {
        let per = |ns: u128| (ns as f64) / 1000.0 / (r.batch as f64);
        println!(
            "{:<20}  {:>8}  {:>13.3}  {:>10.3}  {:>10.3}  {:>10.3}  {:>14.1}  {:>11}",
            r.label,
            r.out_bits,
            per(r.t_sample_ns),
            per(r.t_h_ns),
            per(r.t_verify_ns),
            per(r.t_superinv_ns),
            (r.t_superinv_build_ns as f64) / 1000.0,
            r.wire_bytes,
        );
    }
}

fn print_reconstruction_table(rows: &[BenchRow]) {
    println!("Table 2 — Lagrange reconstruction: basis rebuilt per call vs cached");
    println!(
        "{:<20}  {:>12}  {:>12}  {:>12}  {:>9}  {:>14}",
        "profile", "uncached", "basis.build", "cached", "ratio", "cache hit/miss",
    );
    println!(
        "{:<20}  {:>12}  {:>12}  {:>12}  {:>9}  {:>14}",
        "", "(μs/coin)", "(μs once)", "(μs/coin)", "unc/cach", "",
    );
    println!("{}", "-".repeat(94));
    for r in rows {
        let per = |ns: u128| (ns as f64) / 1000.0 / (r.batch as f64);
        let cached = per(r.t_lagrange_cached_ns);
        let (unc_str, ratio_str) = match r.t_lagrange_uncached_ns {
            Some(ns) => {
                let unc = per(ns);
                let ratio = if cached > 0.0 {
                    format!("{:.1}x", unc / cached)
                } else {
                    "n/a".to_string()
                };
                (format!("{:.3}", unc), ratio)
            }
            None => ("n/a".to_string(), "n/a".to_string()),
        };
        println!(
            "{:<20}  {:>12}  {:>12.1}  {:>12.3}  {:>9}  {:>14}",
            r.label,
            unc_str,
            (r.t_lagrange_build_ns as f64) / 1000.0,
            cached,
            ratio_str,
            format!("{}/{}", r.cache_hits, r.cache_misses),
        );
    }
    println!();
    println!("  BigUint shows `n/a` for `uncached` because `BatchExtractor` has always held the");
    println!("  basis — it has no rebuild-per-call mode. Its `cached` column and the GF2 `cached`");
    println!(
        "  column measure the same thing; its `basis.build` is `BatchExtractor::new`. The GF2"
    );
    println!("  `uncached` column is the pre-change GF2 behaviour, not a BigUint workload.");
}

fn print_arith_table(rows: &[BenchRow]) {
    println!("Table 3 — large×small multiplication: general tower mul vs mul_small fast path");
    println!(
        "{:<20}  {:>10}  {:>12}  {:>12}  {:>9}",
        "profile", "ops", "mul", "mul_small", "ratio",
    );
    println!(
        "{:<20}  {:>10}  {:>12}  {:>12}  {:>9}",
        "", "", "(ns/op)", "(ns/op)", "mul/small",
    );
    println!("{}", "-".repeat(72));
    for r in rows {
        match &r.arith {
            Some(a) => {
                let ns = |total: u128| (total as f64) / (a.ops as f64);
                let general = ns(a.t_mul_ns);
                let small = ns(a.t_mul_small_ns);
                println!(
                    "{:<20}  {:>10}  {:>12.2}  {:>12.2}  {:>9}",
                    r.label,
                    a.ops,
                    general,
                    small,
                    if small > 0.0 {
                        format!("{:.2}x", general / small)
                    } else {
                        "n/a".to_string()
                    },
                );
            }
            None => println!(
                "{:<20}  {:>10}  {:>12}  {:>12}  {:>9}",
                r.label, "-", "n/a", "n/a", "n/a"
            ),
        }
    }
    println!();
    println!("  Every row asserts `a.mul(b) == a.mul_small(b)` on random inputs before timing, so");
    println!(
        "  these are timings of arithmetic that was checked to be correct. Rows with w_p == w_q"
    );
    println!("  have no subfield to exploit; a ratio near 1.0x there is the expected result.");
}

/// Demonstrate that configurations exceeding the small field's point
/// capacity are *rejected*, not silently truncated into aliased
/// evaluation points.
fn report_capacity_rejections(t: usize) {
    println!("Point-capacity enforcement (all of these must be rejected)");
    for &(w_p, w_q, n_try) in &[(8usize, 64usize, 300usize), (8, 256, 512), (16, 64, 70_000)] {
        let prof = match Gf2Profile::new(w_p, w_q) {
            Ok(p) => p,
            Err(e) => {
                println!("  GF2({},{}) unavailable: {}", w_p, w_q, e);
                continue;
            }
        };
        match Gf2TwoFieldDealer::new(prof, t, n_try) {
            Ok(_) => println!(
                "  !! GF2({},{}) n={} ACCEPTED — capacity check is broken",
                w_p, w_q, n_try
            ),
            Err(e) => println!("  GF2({},{}) n={:<6} rejected: {}", w_p, w_q, n_try, e),
        }
    }

    // The extractor's β points live above max(α); exhausting that
    // budget must fail rather than wrap onto an α point.
    if let Ok(prof) = Gf2Profile::new(8, 64) {
        let alphas: Vec<usize> = (1..=200).collect();
        match Gf2SuperInvExtractor::new(prof, alphas, 100) {
            Ok(_) => println!("  !! GF2(  8, 64) m=200 R=100 ACCEPTED — β budget check is broken"),
            Err(e) => println!("  GF2(  8, 64) m=200 R=100 rejected: {}", e),
        }
        match check_point_set(prof, &[1, 2, 2, 3]) {
            Ok(()) => println!("  !! duplicate point set ACCEPTED — collision check is broken"),
            Err(e) => println!("  duplicate point set rejected: {}", e),
        }
    }
}

fn print_notes(n: usize, f: usize, t: usize) {
    println!("Notes");
    println!("  * `dealer.sample`: sample f (small-field coefficients) and g (large-field),");
    println!(
        "    then evaluate both at all n={} recipient points. Per dealer per round the cost",
        n
    );
    println!("    is `dealer.sample × batch`.");
    println!("  * `dealer.h`: compute h(x) = g(x) + θ·f(x) (char 2: + and − coincide), always");
    println!("    emitted with exactly f+1 = {} coefficients.", t);
    println!("  * `verify`: one honest recipient's full verify_share for the whole batch,");
    println!("    including the canonical-length degree bound and the small-field membership");
    println!("    check, plus the BigUint-mode cross-binding check. Divided by batch.");
    println!(
        "  * `superinv`: extraction over all n decided dealers, producing m−f = {} outputs",
        n - f
    );
    println!("    per coin column. `superinv.build` is the one-off matrix construction and is");
    println!("    NOT included in the per-coin number — it is shown separately on purpose.");
    println!("  * `out_bits` is the entropy of ONE recovered secret, i.e. w_p. Rows with");
    println!("    different w_p do not produce the same number of random bits per coin, so");
    println!("    per-coin times are not directly comparable across those rows.");
    println!("  * GF2(64,64) and GF2(128,128) are same-field ARITHMETIC baselines. They do not");
    println!("    meet the PPT challenge-domain requirement q > 2^(128+n); do not read them as");
    println!("    same-security-level protocol baselines.");
    println!("  * `wire_B/rcpt` counts the serialized AvssRecipientPayload for ONE recipient:");
    println!("    SHARE BYTES ONLY. Merkle proofs, dealer broadcast and ACS traffic are NOT");
    println!("    included, so this is not full protocol communication.");
    println!(
        "  * f={} and t={} are fixed across all rows, as are n and batch and the build flags.",
        f, t
    );
}

// =============================================================================
// BigUint baseline
// =============================================================================

fn bench_biguint(n: usize, f: usize, t: usize, batch: usize, spec: &ProfileSpec) -> BenchRow {
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
    //
    // `BatchExtractor` has always precomputed the basis, so there is
    // no uncached mode to measure here. The build cost is timed
    // separately instead of being buried in the per-coin number.
    let eval_points: Vec<usize> = (1..=t).collect();
    let start = Instant::now();
    let extractor = BatchExtractor::new(eval_points.clone(), p.clone());
    let t_lagrange_build_ns = start.elapsed().as_nanos();

    let start = Instant::now();
    let mut recovered = Vec::with_capacity(batch);
    for s in &sampled {
        let shares: Vec<BigUint> = (0..t).map(|i| s.secret_shares[i].1.clone()).collect();
        recovered.push(extractor.recover_one(&shares));
    }
    let t_lagrange_cached_ns = start.elapsed().as_nanos();

    // ----- SuperInvExtractor over decided dealers -----
    let m = n; // assume entire honest set decided
    let alpha_points: Vec<usize> = (1..=m).collect();
    let start = Instant::now();
    let superinv = SuperInvExtractor::new(alpha_points, m - f, p.clone());
    let t_superinv_build_ns = start.elapsed().as_nanos();

    // We need one "decided dealer secret column" per coin. The honest
    // path runs `superinv.extract` once per coin with the m-vector of
    // recovered f_d(0). We reuse the same vector batch times to time.
    let inputs: Vec<BigUint> = (0..m).map(|_| recovered[0].clone()).collect();
    let start = Instant::now();
    for _ in 0..batch {
        let _ = black_box(superinv.extract(&inputs));
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
    let payload = AvssRecipientPayload::new(
        secrets,
        nonces,
        mask_shares,
        Some(f_large_shares),
        Vec::new(),
    );
    let wire_bytes = payload.serialize_bytes().len();

    BenchRow {
        label: spec.label(),
        out_bits: spec.out_bits(),
        batch,
        t_sample_ns,
        t_h_ns,
        t_verify_ns,
        t_superinv_build_ns,
        t_superinv_ns,
        t_lagrange_uncached_ns: None,
        t_lagrange_build_ns,
        t_lagrange_cached_ns,
        cache_hits: 0,
        cache_misses: 0,
        arith: None,
        wire_bytes,
    }
}

// =============================================================================
// GF(2^w) variant
// =============================================================================

fn bench_gf2(
    profile: Gf2Profile,
    dealer: Gf2TwoFieldDealer,
    n: usize,
    f: usize,
    t: usize,
    batch: usize,
    spec: &ProfileSpec,
) -> BenchRow {
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

    // ----- Lagrange recovery: uncached, basis build, cached -----
    let point_ids: Vec<usize> = (1..=t).collect();
    let share_sets: Vec<Vec<(usize, Gf2Element)>> = sampled
        .iter()
        .map(|s| s.secret_shares.iter().take(t).copied().collect())
        .collect();

    let start = Instant::now();
    let mut recovered = Vec::with_capacity(batch);
    for points in &share_sets {
        recovered.push(
            lagrange_recover_at_zero(profile, points)
                .unwrap_or_else(|e| panic!("uncached recovery failed: {}", e)),
        );
    }
    let t_lagrange_uncached_ns = start.elapsed().as_nanos();

    // One-off basis build, averaged over enough repetitions that the
    // clock resolution is not the dominant term.
    const BASIS_REPS: usize = 64;
    let start = Instant::now();
    for _ in 0..BASIS_REPS {
        let basis = Gf2LagrangeBasis::new(profile, &point_ids)
            .unwrap_or_else(|e| panic!("basis build failed: {}", e));
        black_box(basis.len());
    }
    let t_lagrange_build_ns = start.elapsed().as_nanos() / (BASIS_REPS as u128);

    let mut cache = Gf2LagrangeCache::new(profile);
    let start = Instant::now();
    let mut recovered_cached = Vec::with_capacity(batch);
    for points in &share_sets {
        recovered_cached.push(
            cache
                .recover_at_zero(points)
                .unwrap_or_else(|e| panic!("cached recovery failed: {}", e)),
        );
    }
    let t_lagrange_cached_ns = start.elapsed().as_nanos();
    let (cache_hits, cache_misses) = cache.stats();
    assert_eq!(
        recovered, recovered_cached,
        "cached Lagrange recovery must agree with the uncached path"
    );

    // ----- Gf2SuperInvExtractor over decided dealers -----
    let m = n;
    let alpha_points: Vec<usize> = (1..=m).collect();
    let start = Instant::now();
    let superinv = Gf2SuperInvExtractor::new(profile, alpha_points, m - f)
        .unwrap_or_else(|e| panic!("super-invertible extractor rejected the point set: {}", e));
    let t_superinv_build_ns = start.elapsed().as_nanos();

    let inputs: Vec<Gf2Element> = (0..m).map(|_| recovered[0]).collect();
    let start = Instant::now();
    for _ in 0..batch {
        let _ = black_box(superinv.extract(&inputs));
    }
    let t_superinv_ns = start.elapsed().as_nanos();

    let arith = bench_mul_small(profile, &mut rng);

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
    let payload = AvssRecipientPayload::new(secrets, nonces, mask_shares, None, Vec::new());
    let wire_bytes = payload.serialize_bytes().len();

    BenchRow {
        label: spec.label(),
        out_bits: spec.out_bits(),
        batch,
        t_sample_ns,
        t_h_ns,
        t_verify_ns,
        t_superinv_build_ns,
        t_superinv_ns,
        t_lagrange_uncached_ns: Some(t_lagrange_uncached_ns),
        t_lagrange_build_ns,
        t_lagrange_cached_ns,
        cache_hits,
        cache_misses,
        arith: Some(arith),
        wire_bytes,
    }
}

/// Time `mul` against `mul_small` for a large operand times a
/// base-field operand, after checking on random inputs that the two
/// agree. Timing arithmetic without first confirming it is correct
/// would make the number meaningless.
fn bench_mul_small<R: rand::Rng>(profile: Gf2Profile, rng: &mut R) -> ArithRow {
    const OPS: usize = 200_000;

    let random_small = |rng: &mut R| loop {
        let mut bytes = vec![0u8; profile.small_byte_len()];
        rng.fill(&mut bytes[..]);
        let e = Gf2Element::lift_small(profile, &bytes);
        if !e.is_zero() {
            return e;
        }
    };
    let random_large = |rng: &mut R| loop {
        let mut buf = [0u8; 32];
        rng.fill(&mut buf[..]);
        let e = Gf2Element::from_random_bytes(profile, buf);
        if !e.is_zero() {
            return e;
        }
    };

    for _ in 0..256 {
        let a = random_large(rng);
        let b = random_small(rng);
        assert_eq!(
            a.mul(&b),
            a.mul_small(&b),
            "mul_small disagrees with the general multiplication on {:?}",
            profile
        );
    }
    let zero = Gf2Element::zero(profile);
    let one = Gf2Element::one(profile);
    for a in [zero, one, random_large(rng)] {
        for b in [zero, one, random_small(rng)] {
            assert_eq!(a.mul(&b), a.mul_small(&b), "mul_small edge case mismatch");
        }
    }

    let a0 = random_large(rng);
    let b = random_small(rng);

    // Chained so each product feeds the next: the dependency chain
    // stops the loop from being hoisted, and a product of nonzero
    // field elements is nonzero, so the operands stay representative.
    let start = Instant::now();
    let mut acc = a0;
    for _ in 0..OPS {
        acc = black_box(acc.mul(&b));
    }
    let t_mul_ns = start.elapsed().as_nanos();
    black_box(acc);

    let start = Instant::now();
    let mut acc = a0;
    for _ in 0..OPS {
        acc = black_box(acc.mul_small(&b));
    }
    let t_mul_small_ns = start.elapsed().as_nanos();
    black_box(acc);

    ArithRow {
        ops: OPS,
        t_mul_ns,
        t_mul_small_ns,
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn gf2(w_p: usize, w_q: usize) -> ProfileSpec {
        ProfileSpec::Gf2(Gf2Profile::new(w_p, w_q).unwrap())
    }

    #[test]
    fn single_profile_with_internal_comma_survives_parsing() {
        assert_eq!(
            parse_profiles(Some("GF2(32,256)".to_string())),
            vec![gf2(32, 256)]
        );
    }

    #[test]
    fn multiple_profiles_split_only_at_top_level() {
        assert_eq!(
            parse_profiles(Some("BigUint,GF2(64,256),GF2(32,256)".to_string())),
            vec![ProfileSpec::BigUint, gf2(64, 256), gf2(32, 256)]
        );
    }

    #[test]
    fn semicolons_whitespace_and_newlines_separate() {
        assert_eq!(
            parse_profiles(Some("GF2(32,256); GF2(8,64)\nGF2(128,128)".to_string())),
            vec![gf2(32, 256), gf2(8, 64), gf2(128, 128)]
        );
    }

    #[test]
    fn spaces_inside_a_spec_do_not_split_it() {
        assert_eq!(
            parse_profiles(Some("GF2( 32 , 256 )".to_string())),
            vec![gf2(32, 256)]
        );
    }

    #[test]
    fn biguint_tag_is_case_insensitive() {
        assert_eq!(
            parse_profiles(Some("biguint".to_string())),
            vec![ProfileSpec::BigUint]
        );
    }

    #[test]
    fn invalid_tokens_are_skipped_not_silently_substituted() {
        // `GF2(24,64)`: 24 does not divide 64, so there is no subfield
        // embedding. It must drop out rather than be swapped for a
        // nearby legal profile.
        let parsed = parse_profiles(Some("GF2(24,64),GF2(32,256)".to_string()));
        assert_eq!(parsed, vec![gf2(32, 256)]);
    }

    #[test]
    fn bare_unparenthesized_pair_is_rejected_with_a_hint() {
        // `64,256` is two top-level tokens; neither parses alone.
        assert!(parse_profiles(Some("64,256".to_string())).is_empty());
        let err = parse_profile_token("64").unwrap_err();
        assert!(err.contains("parentheses"), "unhelpful error: {}", err);
    }

    #[test]
    fn empty_list_yields_no_profiles() {
        assert!(parse_profiles(Some("  ,, ; ".to_string())).is_empty());
    }

    #[test]
    fn default_sweep_covers_the_required_profiles() {
        let parsed = parse_profiles(None);
        assert_eq!(parsed[0], ProfileSpec::BigUint);
        for &(w_p, w_q) in DEFAULT_GF2_PROFILES.iter() {
            assert!(
                parsed.contains(&gf2(w_p, w_q)),
                "default sweep is missing GF2({},{})",
                w_p,
                w_q
            );
        }
    }

    #[test]
    fn out_bits_reports_the_small_field_width() {
        // The secret lives in GF(2^w_p); a GF2(8,256) coin carries 8
        // bits of entropy, not 256.
        assert_eq!(gf2(8, 256).out_bits(), 8);
        assert_eq!(gf2(128, 256).out_bits(), 128);
    }
}
