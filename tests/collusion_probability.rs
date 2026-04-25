//! Property-based (B-stat) test for committee-collusion probability.
//!
//! Encodes `hypotheses/collusion-probability.md` (SPEC.md §7.1 + §9.1,
//! class B-stat). Claim: the probability that a specific pre-chosen
//! set of `k` colluding runners are all selected onto the same
//! committee of size `k` (drawn without replacement from a fleet of
//! `N`) is bounded by `1 / C(N, k)` under honest VRF.
//!
//! **Primitive stand-in:** same SHA-256-as-VRF reasoning as
//! `scheduling-fairness` — VRF correctness is covered by
//! `vrf-assignment-uniformity` (Tier 1 ✓); here we only need a fast,
//! unbiased, deterministic-in-input selection function.

use std::collections::HashSet;

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use sha2::{Digest, Sha256};

use hegel::generators;

const N_INNER: usize = 15;
const N_JOBS_PER_INNER: usize = 5_000;
/// Additive slack on the theoretical bound. Absolute rather than
/// multiplicative so very-small theoretical rates still have headroom
/// against small-sample noise.
const TOLERANCE: f64 = 0.015;

/// Score runner i for a job seed: SHA-256(seed || i).
fn score(seed: &[u8; 32], runner: usize) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(seed);
    h.update((runner as u64).to_le_bytes());
    h.finalize().into()
}

/// Top-k committee under pick-smallest-hash rule.
fn pick_top_k(seed: &[u8; 32], n_runners: usize, k: usize) -> HashSet<usize> {
    let mut scored: Vec<([u8; 32], usize)> = (0..n_runners).map(|i| (score(seed, i), i)).collect();
    scored.sort_by(|a, b| a.0.cmp(&b.0));
    scored.into_iter().take(k).map(|(_, i)| i).collect()
}

/// Theoretical bound on P(specific k colluders all on committee of size k).
fn theoretical_prob(n: usize, k: usize) -> f64 {
    // 1 / C(n, k) = k! * (n-k)! / n! = product_{i=0..k-1} (k-i)/(n-i)
    let mut p = 1.0;
    for i in 0..k {
        p *= (k - i) as f64 / (n - i) as f64;
    }
    p
}

fn simulate_empirical_rate(n_runners: usize, k: usize, n_jobs: usize, rng: &mut ChaCha8Rng) -> f64 {
    // Fix colluders to the first k runner indices.
    let colluders: HashSet<usize> = (0..k).collect();
    let mut hits = 0_usize;
    for _ in 0..n_jobs {
        let mut seed = [0_u8; 32];
        rng.fill_bytes(&mut seed);
        if pick_top_k(&seed, n_runners, k) == colluders {
            hits += 1;
        }
    }
    hits as f64 / n_jobs as f64
}

#[hegel::test(test_cases = 10)]
fn empirical_collusion_rate_within_bound(tc: hegel::TestCase) {
    // k ∈ [2, 5]. Small k keeps C(N, k) sizable for interesting
    // theoretical bounds without dominating the test.
    let k = tc.draw(generators::integers::<usize>().min_value(2).max_value(5));
    // N ∈ [k+1, 30]. Avoid N == k (trivially 100% collusion probability).
    let n = tc.draw(
        generators::integers::<usize>()
            .min_value(k + 1)
            .max_value(30),
    );
    let seed = tc.draw(generators::integers::<u64>());

    let mut rates: Vec<f64> = Vec::with_capacity(N_INNER);
    for inner in 0..N_INNER {
        let mut rng = ChaCha8Rng::seed_from_u64(seed.wrapping_add(inner as u64));
        rates.push(simulate_empirical_rate(n, k, N_JOBS_PER_INNER, &mut rng));
    }
    let mean = rates.iter().sum::<f64>() / N_INNER as f64;
    let bound = theoretical_prob(n, k);

    assert!(
        mean <= bound + TOLERANCE,
        "empirical collusion rate {} exceeds bound {} + tol {} (n={}, k={}, seed={})",
        mean,
        bound,
        TOLERANCE,
        n,
        k,
        seed
    );
}
