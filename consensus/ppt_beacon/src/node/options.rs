//! Deployment assumptions are explicit and do not alter microbenchmark defaults.
use anyhow::{anyhow, Result};
use crypto::gf2::Gf2Profile;
use config::Node;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PptChannel { Benchmark, Private, ExternalPrivate }

/// Number of independent degree-test repetitions — `R` in Shoup-Smart
/// 2024 §5.1. The dealer broadcasts one `h` per coin under a single
/// shared `θ`, which is `R = 1`. Raising it is the only way to buy
/// soundness once `w_q` sits at `crypto::gf2::MAX_LARGE_WIDTH`, so the
/// budget formulas below take it as an argument rather than inlining 1.
pub const PPT_DEGREE_TEST_REPETITIONS: usize = 1;

/// How many random-oracle queries the degree-test budget assumes a
/// grinding dealer can spend.
///
/// Shoup-Smart 2024 bounds the degree test's failure probability two
/// different ways depending on where the challenge comes from:
///
/// * Theorem 5.1, challenge from an external beacon: `2^n · χ^R`.
/// * Theorem 7.1, challenge from a random oracle: `Q · 2^n · χ^R`,
///   where `Q` counts grinds on `F_Dst3move` and is bounded in the
///   reduction by the adversary's random-oracle queries.
///
/// This codebase derives `θ` from the dealer's own commitment, so
/// Theorem 7.1 is the applicable bound and `Q` has to be budgeted
/// explicitly. The variants differ only in how `Q` relates to the
/// security level being claimed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PptGrindBudget {
    /// `Q = 2^80`. Asserts the dealer will not spend more than 2^80
    /// offline hash evaluations on grinding. Classical adversaries only.
    Offline80,
    /// `Q = 2^σ`. The grinding budget equals the security level under
    /// attack — the usual Fiat-Shamir convention, and the default.
    Matched,
    /// `Q = 2^{2σ}`. Grover-amplified grinding: a quantum adversary
    /// making `T` queries hits a marked fraction `p` with roughly
    /// `T²·p`, so σ bits costs `3σ` bits of challenge material. This
    /// is the conservative convention, not a result from the paper,
    /// which does no post-quantum accounting.
    Grover,
}

impl PptGrindBudget {
    /// Bits of challenge material consumed per bit of claimed security.
    fn sigma_cost(self) -> usize {
        match self { Self::Offline80 => 1, Self::Matched => 2, Self::Grover => 3 }
    }

    /// Bits of challenge material consumed regardless of σ.
    fn fixed_cost(self) -> usize {
        match self { Self::Offline80 => 80, Self::Matched | Self::Grover => 0 }
    }

    pub fn describe(self) -> &'static str {
        match self {
            Self::Offline80 => "Q=2^80 (asserted offline grinding budget)",
            Self::Matched => "Q=2^sigma (matched grinding budget)",
            Self::Grover => "Q=2^2sigma (Grover-amplified grinding)",
        }
    }
}

fn ceil_log2(value: usize) -> usize {
    match value {
        0 | 1 => 0,
        v => (usize::BITS - (v - 1).leading_zeros()) as usize,
    }
}

/// Bits of soundness the Fiat-Shamir degree test actually provides.
///
/// A single `θ` covers all `coins` per-coin identities, and the dealer
/// wins as soon as any one coin's leading term cancels, so the union
/// bound carries a `coins` factor on top of Theorem 5.1's `2^n` bound
/// over the possible happy subsets:
///
/// ```text
/// failure <= Q · coins · 2^n · 2^{-R·w_q}
/// ```
///
/// Solving that for σ under the selected `Q` budget gives
/// `R·w_q >= sigma_cost·σ + n + log2(coins) + fixed_cost`.
pub fn degree_test_soundness_bits(
    w_q: usize,
    repetitions: usize,
    num_nodes: usize,
    coins: usize,
    budget: PptGrindBudget,
) -> usize {
    let challenge_bits = repetitions.saturating_mul(w_q);
    let overhead = num_nodes
        .saturating_add(ceil_log2(coins))
        .saturating_add(budget.fixed_cost());
    challenge_bits.saturating_sub(overhead) / budget.sigma_cost()
}

/// Smallest `R` that reaches `target` bits at the given width, so the
/// startup error can say what would actually fix the configuration.
pub fn degree_test_repetitions_for(
    target: usize,
    w_q: usize,
    num_nodes: usize,
    coins: usize,
    budget: PptGrindBudget,
) -> usize {
    if w_q == 0 { return usize::MAX; }
    let needed = budget
        .sigma_cost()
        .saturating_mul(target)
        .saturating_add(num_nodes)
        .saturating_add(ceil_log2(coins))
        .saturating_add(budget.fixed_cost());
    (needed + w_q - 1) / w_q
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PptOptions {
    pub channel: PptChannel,
    pub target128: bool,
    pub grind_budget: PptGrindBudget,
}

impl Default for PptOptions {
    fn default() -> Self {
        Self {
            channel: PptChannel::Benchmark,
            target128: false,
            grind_budget: PptGrindBudget::Matched,
        }
    }
}

impl PptOptions {
    pub fn parse(channel: &str, security: &str, grind_budget: &str) -> Result<Self> {
        let channel = match channel {
            "benchmark" => PptChannel::Benchmark,
            "private" => PptChannel::Private,
            "external-private" => PptChannel::ExternalPrivate,
            _ => return Err(anyhow!("--ppt-channel must be benchmark, private or external-private")),
        };
        let target128 = match security {
            "benchmark" => false,
            "target128" => true,
            _ => return Err(anyhow!("--ppt-security must be benchmark or target128")),
        };
        let grind_budget = match grind_budget {
            "matched" => PptGrindBudget::Matched,
            "grover" => PptGrindBudget::Grover,
            "offline80" => PptGrindBudget::Offline80,
            _ => return Err(anyhow!("--ppt-grind-budget must be matched, grover or offline80")),
        };
        Ok(Self { channel, target128, grind_budget })
    }

    pub(crate) fn validate(
        self,
        config: &Node,
        profile: Option<Gf2Profile>,
        transport: super::context::AvssTransport,
        batch: usize,
    ) -> Result<()> {
        if self.channel == PptChannel::Private {
            for peer in 0..config.num_nodes {
                if peer != config.id && config.sk_map.get(&peer).map(|key| key.len()) != Some(32) {
                    return Err(anyhow!("PPT private channel needs a provisioned 32-byte secret for every peer"));
                }
            }
        }
        let coins = batch.saturating_add(super::context::PPT_COIN_RESERVE);
        match profile {
            Some(p) => {
                let achieved = degree_test_soundness_bits(
                    p.w_q, PPT_DEGREE_TEST_REPETITIONS, config.num_nodes, coins, self.grind_budget,
                );
                log::info!(
                    "[PPT][SOUNDNESS] degree test: w_q={} R={} n={} coins={} budget={} -> {} bits (Shoup-Smart 2024 Thm 7.1: Q·2^n·chi^R)",
                    p.w_q, PPT_DEGREE_TEST_REPETITIONS, config.num_nodes, coins,
                    self.grind_budget.describe(), achieved,
                );
            }
            None => log::warn!(
                "[PPT][SOUNDNESS] prime-field comparison mode claims no degree-test bound: F_q is not an extension of F_p, so Thm 5.1's shared check matrix does not apply and the bound does not transfer to the small-field shares"
            ),
        }
        if self.target128 {
            if transport != super::context::AvssTransport::SecMsg {
                return Err(anyhow!("target128 requires SecMsg's transferable recovery evidence; Lite remains an explicit private-channel comparison"));
            }
            if self.channel == PptChannel::Benchmark {
                return Err(anyhow!("target128 requires private or an explicitly asserted external-private channel"));
            }
            let profile = profile.ok_or_else(|| anyhow!("target128 requires a true GF2 extension; legacy prime fields are a comparison mode"))?;
            let achieved = degree_test_soundness_bits(
                profile.w_q, PPT_DEGREE_TEST_REPETITIONS, config.num_nodes, coins, self.grind_budget,
            );
            if achieved < 128 {
                let needed_r = degree_test_repetitions_for(
                    128, profile.w_q, config.num_nodes, coins, self.grind_budget,
                );
                return Err(anyhow!(
                    "PPT target128 reaches only {} bits: the Fiat-Shamir challenge is ground against the dealer's own commitment, so Shoup-Smart Thm 7.1 requires R*w_q >= {}*128 + n + log2(coins) under {}. With w_q={} n={} coins={} and R={} that is {} < {} bits; raise R to {} or widen w_q (capped at MAX_LARGE_WIDTH=256), or select --ppt-grind-budget offline80 to assert a weaker grinding budget",
                    achieved,
                    self.grind_budget.sigma_cost(),
                    self.grind_budget.describe(),
                    profile.w_q, config.num_nodes, coins, PPT_DEGREE_TEST_REPETITIONS,
                    achieved, 128, needed_r,
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const N: usize = 16;
    const COINS: usize = 1012; // batch 1000 + PPT_COIN_RESERVE

    #[test]
    fn ceil_log2_matches_union_bound_exponent() {
        assert_eq!(ceil_log2(0), 0);
        assert_eq!(ceil_log2(1), 0);
        assert_eq!(ceil_log2(2), 1);
        assert_eq!(ceil_log2(1012), 10);
        assert_eq!(ceil_log2(1024), 10);
        assert_eq!(ceil_log2(1025), 11);
    }

    /// The superseded check was `w_q > 128 + n`, which is Theorem 5.1's
    /// external-beacon bound — it budgets no grinding at all. Under the
    /// applicable Theorem 7.1 bound the same width buys far less.
    #[test]
    fn matched_budget_is_short_of_128_at_max_width() {
        let bits = degree_test_soundness_bits(256, 1, N, COINS, PptGrindBudget::Matched);
        assert_eq!(bits, (256 - 16 - 10) / 2);
        assert!(bits < 128, "w_q=256 R=1 must not claim 128 bits once Q is budgeted");
        assert_eq!(degree_test_repetitions_for(128, 256, N, COINS, PptGrindBudget::Matched), 2);
    }

    /// Two repetitions clear 128 bits with room to spare, so `R` never
    /// has to go past 2 at the maximum width.
    #[test]
    fn two_repetitions_clear_128_bits() {
        for budget in [PptGrindBudget::Matched, PptGrindBudget::Grover] {
            let bits = degree_test_soundness_bits(256, 2, N, COINS, budget);
            assert!(bits >= 128, "{:?} reached only {} bits at R=2", budget, bits);
            assert_eq!(degree_test_repetitions_for(128, 256, N, COINS, budget), 2);
        }
    }

    /// Grover accounting is strictly more demanding than matched, which
    /// is strictly more demanding than an asserted 2^80 budget.
    #[test]
    fn budgets_are_ordered() {
        let matched = degree_test_soundness_bits(256, 1, N, COINS, PptGrindBudget::Matched);
        let grover = degree_test_soundness_bits(256, 1, N, COINS, PptGrindBudget::Grover);
        let offline = degree_test_soundness_bits(256, 1, N, COINS, PptGrindBudget::Offline80);
        assert!(grover < matched && matched < offline);
        // offline80 is the only budget that still clears 128 at R=1.
        assert!(offline >= 128);
        assert_eq!(degree_test_repetitions_for(128, 256, N, COINS, PptGrindBudget::Offline80), 1);
    }

    /// The batch factor is a union bound over coins sharing one θ, so
    /// it costs log2(coins) bits — and removing it does not by itself
    /// rescue R=1 under the matched budget.
    #[test]
    fn batch_factor_is_not_the_binding_constraint() {
        let shared = degree_test_soundness_bits(256, 1, N, COINS, PptGrindBudget::Matched);
        let combined = degree_test_soundness_bits(256, 1, N, 1, PptGrindBudget::Matched);
        assert_eq!(combined - shared, 10 / 2);
        assert!(combined < 128, "batching alone must not be mistaken for a fix");
    }

    #[test]
    fn grind_budget_parsing_round_trips() {
        for (text, expected) in [
            ("matched", PptGrindBudget::Matched),
            ("grover", PptGrindBudget::Grover),
            ("offline80", PptGrindBudget::Offline80),
        ] {
            let parsed = PptOptions::parse("benchmark", "benchmark", text).unwrap();
            assert_eq!(parsed.grind_budget, expected);
        }
        assert!(PptOptions::parse("benchmark", "benchmark", "none").is_err());
        assert_eq!(PptOptions::default().grind_budget, PptGrindBudget::Matched);
    }
}
