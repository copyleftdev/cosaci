//! Property-based (B-stat) test for gossip propagation time.
//!
//! Encodes `hypotheses/gossip-propagation-time.md` (SPEC.md §12.3,
//! class B-stat). Abstract push-gossip simulator (no wall time; round-
//! based; each infected node pushes to `fanout` random peers per round).
//! Claim: mean rounds to full propagation ≤ `C · log_f N`.
//!
//! Convergence-at-all is the class-A `gossip-convergence-invariant`
//! card (already passing, `src/gossip.rs`). This card tests the
//! *time* to convergence, which is why it's B-stat (averaged over
//! topology randomness).

use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha8Rng;

use hegel::generators;

const N_INNER: usize = 50;
// Propagation-time constant: mean rounds ≤ C · log_f(N). Theoretical
// push-gossip analyses give C around 1 + ε; we use 4 as a very loose
// upper bound that still catches catastrophic regressions (e.g., a
// gossip bug that degrades to linear propagation).
const C: f64 = 4.0;

fn simulate_push_gossip(n: usize, fanout: usize, rng: &mut ChaCha8Rng) -> usize {
    let mut infected = vec![false; n];
    infected[0] = true;

    let mut rounds = 0_usize;
    let max_rounds = n * 4;
    while !infected.iter().all(|&b| b) && rounds < max_rounds {
        let mut new_this_round = vec![false; n];
        for i in 0..n {
            if !infected[i] {
                continue;
            }
            for _ in 0..fanout {
                let target: usize = rng.random_range(0..n);
                if target != i {
                    new_this_round[target] = true;
                }
            }
        }
        for i in 0..n {
            if new_this_round[i] {
                infected[i] = true;
            }
        }
        rounds += 1;
    }
    rounds
}

#[hegel::test(test_cases = 15)]
fn gossip_propagates_within_log_bound(tc: hegel::TestCase) {
    let n = tc.draw(generators::integers::<usize>().min_value(4).max_value(100));
    let fanout = tc.draw(generators::integers::<usize>().min_value(2).max_value(8));
    let seed = tc.draw(generators::integers::<u64>());

    let mut rounds_list = Vec::with_capacity(N_INNER);
    for inner in 0..N_INNER {
        let mut rng = ChaCha8Rng::seed_from_u64(seed.wrapping_add(inner as u64));
        rounds_list.push(simulate_push_gossip(n, fanout, &mut rng));
    }

    let mean_rounds: f64 = rounds_list.iter().sum::<usize>() as f64 / N_INNER as f64;

    let log_f_n = (n as f64).ln() / (fanout as f64).ln();
    let bar = C * log_f_n.max(1.0);

    assert!(
        mean_rounds <= bar,
        "mean propagation rounds {} exceeds bar {} (n={}, fanout={}, C={}, log_f_n={})",
        mean_rounds,
        bar,
        n,
        fanout,
        C,
        log_f_n
    );
}
