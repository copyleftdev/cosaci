//! Property-based (B-stat) test for Sybil resistance of stake-weighted quorum.
//!
//! Encodes `hypotheses/sybil-resistance.md` (SPEC.md §9.1, class B-stat).
//! A Sybil attacker controls fraction `s` of total stake, split across `k`
//! synthetic identities. Under a 2/3-threshold stake-weighted quorum, the
//! attacker cannot get a `PASS` outcome for any `s ∈ [0, 0.5]`, regardless
//! of how they split stake (`k`-insensitivity) or how tightly they
//! coordinate (`coord` — probability each attacker votes Pass).
//!
//! **Design note (first Hegel shrink caught this):** honest voters vote
//! deterministically Fail on a bad commit. Originally the test modeled
//! *honest noise* (each honest votes Pass with prob ~5%); Hegel found that
//! in small fleets (`n_honest = 3`, `noise = 0.04`), all-honest-Pass
//! happens with small-but-nonzero probability and can push past threshold
//! — but that's fleet-reliability noise, not a Sybil achievement. Moving
//! the randomness to the *attacker side* (imperfect coordination) keeps
//! the honest-majority guarantee clean: sybil alone cannot reach
//! threshold when `s ≤ 0.5` against a `2/3` quorum.

use std::collections::HashMap;

use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha8Rng;

use cosaci::quorum::{aggregate, Outcome, RunnerId, StakeMap, Vote, VoteResult, Weight};
use hegel::generators;

const TOTAL_STAKE: u64 = 10_000;
const THRESHOLD_FRACTION: f64 = 2.0 / 3.0;
const N_INNER: usize = 50;

/// Simulate one adversary-authored bad-commit scenario.
///
/// - Adversaries (runner ids `[0, k)`) each vote Pass with probability
///   `coord` ∈ [0, 1]; otherwise Fail.
/// - Honest voters (runner ids `[k, n)`) all vote Fail deterministically.
/// - Quorum is 2/3 of total stake, stake-weighted by `aggregate`.
fn simulate_sybil_attack(
    n_runners: usize,
    sybil_stake_fraction: f64,
    n_sybil_identities: usize,
    coord: f64,
    rng: &mut ChaCha8Rng,
) -> Outcome {
    let k = n_sybil_identities.max(1).min(n_runners);
    let n_honest = n_runners.saturating_sub(k);

    let sybil_total =
        ((sybil_stake_fraction * (TOTAL_STAKE as f64)).round() as u64).min(TOTAL_STAKE);
    let honest_total = TOTAL_STAKE - sybil_total;

    let per_sybil = sybil_total / (k as u64);
    let sybil_rem = (sybil_total % (k as u64)) as usize;
    let per_honest = if n_honest > 0 {
        honest_total / (n_honest as u64)
    } else {
        0
    };
    let honest_rem = if n_honest > 0 {
        (honest_total % (n_honest as u64)) as usize
    } else {
        0
    };

    let mut stake: StakeMap = HashMap::new();
    let mut votes: Vec<Vote> = Vec::new();

    for i in 0..k {
        let runner_id = i as RunnerId;
        let extra = u64::from(i < sybil_rem);
        stake.insert(runner_id, per_sybil + extra);
        let result = if rng.random_bool(coord) {
            VoteResult::Pass
        } else {
            VoteResult::Fail
        };
        votes.push(Vote { runner_id, result });
    }
    for i in 0..n_honest {
        let runner_id = (k + i) as RunnerId;
        let extra = u64::from(i < honest_rem);
        stake.insert(runner_id, per_honest + extra);
        votes.push(Vote {
            runner_id,
            result: VoteResult::Fail,
        });
    }

    let threshold = (THRESHOLD_FRACTION * (TOTAL_STAKE as f64)).ceil() as Weight;
    aggregate(&votes, threshold, &stake)
}

#[hegel::test(test_cases = 15)]
fn sybil_attack_cannot_force_pass(tc: hegel::TestCase) {
    let s_hundredths = tc.draw(
        generators::integers::<u32>()
            .min_value(0)
            .max_value(50),
    );
    let sybil_stake = f64::from(s_hundredths) / 100.0;

    let n_runners = tc.draw(
        generators::integers::<usize>()
            .min_value(10)
            .max_value(60),
    );
    let k_max = (n_runners * 4 / 5).max(1);
    let k = tc.draw(
        generators::integers::<usize>()
            .min_value(1)
            .max_value(k_max),
    );

    // Attacker coordination — bounded to realistic range. At coord=1 the
    // attack is maximally effective; at coord=0 attackers all vote Fail.
    let coord_hundredths = tc.draw(
        generators::integers::<u32>()
            .min_value(50)
            .max_value(100),
    );
    let coord = f64::from(coord_hundredths) / 100.0;

    let seed = tc.draw(generators::integers::<u64>());

    let mut outcomes: HashMap<Outcome, u32> = HashMap::new();
    for inner in 0..N_INNER {
        let mut rng = ChaCha8Rng::seed_from_u64(seed.wrapping_add(inner as u64));
        let outcome =
            simulate_sybil_attack(n_runners, sybil_stake, k, coord, &mut rng);
        *outcomes.entry(outcome).or_insert(0) += 1;
    }

    let pass_count = outcomes.get(&Outcome::Pass).copied().unwrap_or(0);
    assert_eq!(
        pass_count, 0,
        "Sybil attack produced Pass in {} / {} trials (s={}, k={}, n={}, coord={}, outcomes={:?})",
        pass_count, N_INNER, sybil_stake, k, n_runners, coord, outcomes
    );
}

// ----------------------------------------------------------------------------
// k-insensitivity — splitting stake across more sybils doesn't help.
// ----------------------------------------------------------------------------
#[hegel::test(test_cases = 15)]
fn k_does_not_enable_pass(tc: hegel::TestCase) {
    let s_hundredths = tc.draw(
        generators::integers::<u32>()
            .min_value(0)
            .max_value(50),
    );
    let s = f64::from(s_hundredths) / 100.0;
    let n = tc.draw(
        generators::integers::<usize>()
            .min_value(10)
            .max_value(60),
    );
    let coord_h = tc.draw(
        generators::integers::<u32>()
            .min_value(50)
            .max_value(100),
    );
    let coord = f64::from(coord_h) / 100.0;
    let seed = tc.draw(generators::integers::<u64>());

    let k_small: usize = 1;
    let k_large: usize = (n * 4 / 5).max(2);
    if k_small == k_large {
        return;
    }

    let mut rng_a = ChaCha8Rng::seed_from_u64(seed);
    let mut rng_b = ChaCha8Rng::seed_from_u64(seed);
    let outcome_a = simulate_sybil_attack(n, s, k_small, coord, &mut rng_a);
    let outcome_b = simulate_sybil_attack(n, s, k_large, coord, &mut rng_b);

    for outcome in [outcome_a, outcome_b] {
        assert_ne!(
            outcome,
            Outcome::Pass,
            "Sybil achieved Pass via k variation (n={}, s={}, coord={}, seed={})",
            n, s, coord, seed
        );
    }
}
