//! Property-based (B-stat) test for reputation ranking under adversarial load.
//!
//! Encodes `hypotheses/adversarial-reputation-ranking.md` (SPEC.md §8.3b,
//! class B-stat). The **pointwise monotonicity core** of reputation is
//! covered by `reputation-monotonicity` (class A, already passing); this
//! card tests the statistical claim:
//!
//! > At adversary rate `p ∈ [0, 1/3]`, the top-`(1-p)·N` reputation-ranked
//! > runners are overwhelmingly honest.
//!
//! **B-stat test shape** (see `memory/feedback_statistical_vs_universal.md`):
//! Hegel draws distribution parameters `(p, N, T, seed)`; an inner loop
//! of `N_INNER` rounds simulates quorum outcomes via a seeded ChaCha8Rng
//! (the `memory/feedback_seed_driven_scale.md` guidance — inner randomness
//! is too large to route through Hegel directly); the assertion is on the
//! **mean** honest-fraction across inner samples.
//!
//! Using a seeded RNG costs us fine-grained shrinking of individual random
//! decisions, but the failure mode here would be a statistical-bar violation
//! — the distribution parameters `(p, N, T)` are what we want to shrink,
//! not individual coin flips. That's what Hegel shrinks.

use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha8Rng;

use hegel::generators;

/// One simulated quorum episode. Returns the fraction of the top-`n_honest`
/// reputation-ranked runners that are in fact honest.
fn simulate_quorum_episode(
    n_runners: usize,
    adversary_rate: f64,
    n_rounds: usize,
    rng: &mut ChaCha8Rng,
) -> f64 {
    let n_adversaries = ((adversary_rate * n_runners as f64).floor() as usize).min(n_runners);
    let n_honest = n_runners - n_adversaries;
    if n_honest == 0 {
        return 0.0;
    }
    // Runner indices [0, n_adversaries) are adversaries; [n_adversaries, n_runners) are honest.
    let is_adversary: Vec<bool> = (0..n_runners).map(|i| i < n_adversaries).collect();

    // Agreement count per runner (how many rounds their vote == quorum outcome).
    let mut agreements = vec![0_u32; n_runners];

    for _ in 0..n_rounds {
        // "True" outcome for this round (what the honest majority is trying to report).
        let truth = rng.random_bool(0.5);

        // Each runner votes. Honest: truth with 95% reliability; adversary: random.
        let votes: Vec<bool> = (0..n_runners)
            .map(|i| {
                if is_adversary[i] {
                    rng.random_bool(0.5)
                } else if rng.random_bool(0.95) {
                    truth
                } else {
                    !truth
                }
            })
            .collect();

        // Quorum outcome is the simple majority vote (tie broken towards Pass).
        let pass_count = votes.iter().filter(|&&v| v).count();
        let quorum_outcome = pass_count * 2 >= n_runners;

        for i in 0..n_runners {
            if votes[i] == quorum_outcome {
                agreements[i] += 1;
            }
        }
    }

    // Reputation = agreement rate. Sort runners descending by reputation.
    let mut indexed: Vec<(usize, f64)> = agreements
        .iter()
        .enumerate()
        .map(|(i, &a)| (i, f64::from(a) / n_rounds as f64))
        .collect();
    indexed.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    let top = &indexed[..n_honest];
    let honest_in_top = top.iter().filter(|(i, _)| !is_adversary[*i]).count();
    honest_in_top as f64 / n_honest as f64
}

// Number of inner simulation samples per Hegel case. N=50 keeps runtime
// bounded while still smoothing out single-episode noise.
const N_INNER: usize = 50;

// B-stat bar: mean fraction of honest runners in the top-(1-p)·N under
// p ∈ [0, 1/3] should stay above this threshold. 0.95 is intentionally
// loose — honest-majority quorum with random adversaries essentially
// always gives 1.0; we only need protection against catastrophic failures.
const HONEST_FRACTION_BAR: f64 = 0.95;

#[hegel::test(test_cases = 15)]
fn reputation_ranks_adversaries_below_honest(tc: hegel::TestCase) {
    // Distribution parameters drawn by Hegel.
    let p_hundredths = tc.draw(generators::integers::<u32>().min_value(0).max_value(33));
    let p = f64::from(p_hundredths) / 100.0;

    let n_runners = tc.draw(generators::integers::<usize>().min_value(20).max_value(60));
    let n_rounds = tc.draw(generators::integers::<usize>().min_value(30).max_value(80));
    let seed = tc.draw(generators::integers::<u64>());

    // Inner loop: simulate N_INNER episodes with different RNG seeds,
    // average the honest-fraction-in-top-k.
    let mut fractions = Vec::with_capacity(N_INNER);
    for inner in 0..N_INNER {
        let mut rng = ChaCha8Rng::seed_from_u64(seed.wrapping_add(inner as u64));
        fractions.push(simulate_quorum_episode(n_runners, p, n_rounds, &mut rng));
    }
    let mean: f64 = fractions.iter().sum::<f64>() / N_INNER as f64;

    assert!(
        mean >= HONEST_FRACTION_BAR,
        "mean honest fraction {} below bar {} at p={}, n={}, rounds={}, seed={}",
        mean,
        HONEST_FRACTION_BAR,
        p,
        n_runners,
        n_rounds,
        seed
    );
}
