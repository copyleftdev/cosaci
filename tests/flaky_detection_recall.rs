//! Property-based (B-stat) test for flaky-test detection recall.
//!
//! Encodes `hypotheses/flaky-detection-recall.md` (SPEC.md §12.2b,
//! class B-stat). Stresses `cosaci::flake::flake_confidence` as the
//! detection scoring function:
//!
//! 1. Hegel draws injected flakiness rate `p`, total test count `T`,
//!    and per-test run count `K`.
//! 2. Inner loop (seeded ChaCha8Rng) synthesizes `T` tests, marks
//!    `p·T` of them as truly flaky, simulates `K` runs each (flaky:
//!    50/50 pass/fail; stable: all pass), applies the detector, and
//!    computes **recall** (detected-flaky / truly-flaky).
//! 3. Assert mean recall across inner samples ≥ bar.
//!
//! The pointwise monotonicity core of the detection function lives in
//! `flaky-confidence-monotonicity` (class A, already passing).

use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha8Rng;

use cosaci::flake::flake_confidence;
use hegel::generators;

const N_INNER: usize = 50;

/// Any non-zero disagreement is flagged as flaky by the detector.
/// Equivalent to a threshold on `flake_confidence` of just above 0.0.
const DETECTION_THRESHOLD: f64 = 1e-9;

/// Lower bar for mean recall across inner samples. At K=3, expected
/// recall under truly-flaky-is-50/50 is `1 - 2·(0.5)^3 = 0.75`; at K≥5
/// it's > 0.93. Bar 0.55 gives ample headroom against small-sample
/// noise while still catching regressions (e.g., a scoring bug that
/// drops recall to 0).
const RECALL_BAR: f64 = 0.55;

fn simulate_detection(
    n_tests: usize,
    flakiness_rate: f64,
    runs_per_test: usize,
    rng: &mut ChaCha8Rng,
) -> Option<f64> {
    let n_flaky = ((flakiness_rate * n_tests as f64).round() as usize).min(n_tests);
    if n_flaky == 0 {
        return None; // no flaky tests → recall undefined
    }

    let mut detected = 0_usize;
    for _ in 0..n_flaky {
        // Truly-flaky test: each run is a fresh 50/50 coin flip.
        let mut pass_count: u32 = 0;
        for _ in 0..runs_per_test {
            if rng.random_bool(0.5) {
                pass_count += 1;
            }
        }
        let disagreement = pass_count.min(runs_per_test as u32 - pass_count);
        let confidence = flake_confidence(disagreement, runs_per_test as u32);
        if confidence >= DETECTION_THRESHOLD {
            detected += 1;
        }
    }

    // Stable tests: all runs pass, disagreement always 0, confidence 0.
    // They would never be detected; we don't score them here (recall is
    // about flaky tests only). False-positive-rate is a separate claim.

    Some(detected as f64 / n_flaky as f64)
}

#[hegel::test(test_cases = 15)]
fn recall_meets_bar_under_injected_flakiness(tc: hegel::TestCase) {
    // Flakiness rate ∈ [0.10, 0.50] — non-trivial injection.
    let p_hundredths = tc.draw(
        generators::integers::<u32>()
            .min_value(10)
            .max_value(50),
    );
    let p = f64::from(p_hundredths) / 100.0;

    let n_tests = tc.draw(
        generators::integers::<usize>()
            .min_value(50)
            .max_value(200),
    );

    // K ∈ {3, 5, 7, 10}. Discrete choice from a small set.
    let k_idx = tc.draw(generators::integers::<usize>().min_value(0).max_value(3));
    let runs_per_test = [3_usize, 5, 7, 10][k_idx];

    let seed = tc.draw(generators::integers::<u64>());

    let mut recalls: Vec<f64> = Vec::with_capacity(N_INNER);
    for inner in 0..N_INNER {
        let mut rng = ChaCha8Rng::seed_from_u64(seed.wrapping_add(inner as u64));
        if let Some(r) = simulate_detection(n_tests, p, runs_per_test, &mut rng) {
            recalls.push(r);
        }
    }

    if recalls.is_empty() {
        return; // no flaky tests in any inner trial
    }

    let mean = recalls.iter().sum::<f64>() / recalls.len() as f64;

    assert!(
        mean >= RECALL_BAR,
        "mean recall {} below bar {} (p={}, T={}, K={}, seed={})",
        mean, RECALL_BAR, p, n_tests, runs_per_test, seed
    );
}
