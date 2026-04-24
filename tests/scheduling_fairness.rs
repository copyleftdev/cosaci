//! Property-based (B-stat) test for VRF-driven scheduling fairness.
//!
//! Encodes `hypotheses/scheduling-fairness.md` (SPEC.md §7.1, class B-stat).
//! Claim: over many jobs with VRF-based winner selection across a fleet of
//! similar-capability runners, the per-runner job count distribution is
//! fair — Jain's fairness index ≥ `J_min`.
//!
//! **Primitive stand-in:** VRF correctness (deterministic in
//! `(secret_key, input)`; output uniform over the Ristretto255 point
//! group) is covered by `vrf-assignment-uniformity` (Tier 1, passing).
//! Here we need a fast cryptographic hash with the same statistical
//! property — unbiased per `(runner_id, job_seed)` — and substitute
//! SHA-256. A VRF evaluation is ~16ms (schnorrkel), a SHA-256 is ~200ns,
//! so this substitution lets us run `N_INNER=30` trials per Hegel case
//! instead of ~3.

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use sha2::{Digest, Sha256};

use hegel::generators;

const N_INNER: usize = 30;
const JAIN_BAR: f64 = 0.85;

/// Hash-based analogue of VRF winner selection: the runner with the
/// lexicographically smallest SHA-256 of `(job_seed || runner_id)` wins.
fn pick_winner(job_seed: &[u8; 32], n_runners: usize) -> usize {
    let mut min_hash: [u8; 32] = [0xff; 32];
    let mut winner = 0;
    for i in 0..n_runners {
        let mut hasher = Sha256::new();
        hasher.update(job_seed);
        hasher.update(&(i as u64).to_le_bytes());
        let h: [u8; 32] = hasher.finalize().into();
        if h < min_hash {
            min_hash = h;
            winner = i;
        }
    }
    winner
}

/// Jain's fairness index: `(Σ x_i)² / (n · Σ x_i²)`. `1.0` means
/// perfectly equal; `1/n` means one runner got everything.
fn jains_index(counts: &[u32]) -> f64 {
    let n = counts.len() as f64;
    let sum: f64 = counts.iter().map(|&c| f64::from(c)).sum();
    let sum_sq: f64 = counts.iter().map(|&c| f64::from(c) * f64::from(c)).sum();
    if sum_sq == 0.0 {
        return 1.0; // degenerate (no jobs); perfectly equal 0s
    }
    (sum * sum) / (n * sum_sq)
}

fn simulate_fairness_episode(
    n_runners: usize,
    n_jobs: usize,
    rng: &mut ChaCha8Rng,
) -> f64 {
    let mut counts = vec![0_u32; n_runners];
    for _ in 0..n_jobs {
        let mut seed = [0_u8; 32];
        rng.fill_bytes(&mut seed);
        let winner = pick_winner(&seed, n_runners);
        counts[winner] += 1;
    }
    jains_index(&counts)
}

#[hegel::test(test_cases = 15)]
fn jains_index_meets_bar(tc: hegel::TestCase) {
    let n_runners = tc.draw(
        generators::integers::<usize>()
            .min_value(3)
            .max_value(20),
    );
    // Jobs-per-runner drives fairness: low-jobs-per-runner gives higher
    // variance (stochastic bias). Use ≥ 30 jobs-per-runner as a floor.
    let jobs_per_runner = tc.draw(
        generators::integers::<usize>()
            .min_value(30)
            .max_value(200),
    );
    let n_jobs = n_runners * jobs_per_runner;
    let seed = tc.draw(generators::integers::<u64>());

    let mut indices: Vec<f64> = Vec::with_capacity(N_INNER);
    for inner in 0..N_INNER {
        let mut rng = ChaCha8Rng::seed_from_u64(seed.wrapping_add(inner as u64));
        indices.push(simulate_fairness_episode(n_runners, n_jobs, &mut rng));
    }
    let mean = indices.iter().sum::<f64>() / N_INNER as f64;

    assert!(
        mean >= JAIN_BAR,
        "mean Jain's index {} below bar {} (n_runners={}, n_jobs={}, seed={})",
        mean, JAIN_BAR, n_runners, n_jobs, seed
    );
}
