//! Property-based tests for `cosaci::vrf`.
//!
//! Encodes the falsifiable claims of `hypotheses/vrf-assignment-uniformity.md`
//! (SPEC.md §7.1, class A + B-stat sub-claim). Pointwise properties
//! (determinism, verifiability, malleability rejection, cross-key rejection)
//! live here alongside a weak empirical-uniformity check over a simulated
//! winner-selection process. The strong statistical B-stat counterpart is
//! `scheduling-fairness` in Tier 2.

use cosaci::vrf::{verify, VrfKeypair, VrfOutput, VrfProofBytes};
use hegel::{generators, TestCase};

// ----------------------------------------------------------------------------
// Draw helpers
// ----------------------------------------------------------------------------

fn draw_seed(tc: &TestCase) -> [u8; 32] {
    let v: Vec<u8> = tc.draw(generators::binary().min_size(32).max_size(32));
    let mut arr = [0_u8; 32];
    arr.copy_from_slice(&v);
    arr
}

fn draw_input(tc: &TestCase) -> Vec<u8> {
    tc.draw(generators::binary().max_size(64))
}

// ----------------------------------------------------------------------------
// Property 1 — VRF output is deterministic in (key, input).
// The *proof* is randomized (Schnorr nonce) — only the output is pinned.
// ----------------------------------------------------------------------------
#[hegel::test]
fn vrf_output_is_deterministic(tc: hegel::TestCase) {
    let seed = draw_seed(&tc);
    let input = draw_input(&tc);
    let kp = VrfKeypair::from_seed(seed);
    let (out1, _proof1) = kp.evaluate(&input);
    let (out2, _proof2) = kp.evaluate(&input);
    assert_eq!(out1, out2, "VRF output diverged for same (key, input)");
}

// ----------------------------------------------------------------------------
// Property 2 — verify(pk, input, evaluate(sk, input)) = Ok.
// ----------------------------------------------------------------------------
#[hegel::test]
fn vrf_verify_roundtrip(tc: hegel::TestCase) {
    let seed = draw_seed(&tc);
    let input = draw_input(&tc);
    let kp = VrfKeypair::from_seed(seed);
    let pk = kp.public_key_bytes();
    let (out, proof) = kp.evaluate(&input);
    let result = verify(&pk, &input, &out, &proof);
    assert!(result.is_ok(), "valid VRF did not verify: {:?}", result.err());
}

// ----------------------------------------------------------------------------
// Property 3 — output mutation rejects.
// Flipping any single bit of the output must cause verification to fail.
// ----------------------------------------------------------------------------
#[hegel::test]
fn vrf_output_mutation_rejects(tc: hegel::TestCase) {
    let seed = draw_seed(&tc);
    let input = draw_input(&tc);
    let kp = VrfKeypair::from_seed(seed);
    let pk = kp.public_key_bytes();
    let (mut out, proof): (VrfOutput, VrfProofBytes) = kp.evaluate(&input);

    let byte_idx = tc.draw(generators::integers::<usize>().min_value(0).max_value(31));
    let bit_idx = tc.draw(generators::integers::<u8>().min_value(0).max_value(7));
    out[byte_idx] ^= 1_u8 << bit_idx;

    let result = verify(&pk, &input, &out, &proof);
    assert!(
        result.is_err(),
        "verify accepted a mutated VRF output (byte {} bit {})",
        byte_idx,
        bit_idx
    );
}

// ----------------------------------------------------------------------------
// Property 4 — proof mutation rejects.
// ----------------------------------------------------------------------------
#[hegel::test]
fn vrf_proof_mutation_rejects(tc: hegel::TestCase) {
    let seed = draw_seed(&tc);
    let input = draw_input(&tc);
    let kp = VrfKeypair::from_seed(seed);
    let pk = kp.public_key_bytes();
    let (out, mut proof): (VrfOutput, VrfProofBytes) = kp.evaluate(&input);

    let byte_idx = tc.draw(generators::integers::<usize>().min_value(0).max_value(63));
    let bit_idx = tc.draw(generators::integers::<u8>().min_value(0).max_value(7));
    proof[byte_idx] ^= 1_u8 << bit_idx;

    let result = verify(&pk, &input, &out, &proof);
    assert!(
        result.is_err(),
        "verify accepted a mutated VRF proof (byte {} bit {})",
        byte_idx,
        bit_idx
    );
}

// ----------------------------------------------------------------------------
// Property 5 — cross-key rejection.
// ----------------------------------------------------------------------------
#[hegel::test]
fn vrf_cross_key_rejects(tc: hegel::TestCase) {
    let seed_a = draw_seed(&tc);
    let seed_b = draw_seed(&tc);
    if seed_a == seed_b {
        return;
    }
    let input = draw_input(&tc);
    let kp_a = VrfKeypair::from_seed(seed_a);
    let kp_b = VrfKeypair::from_seed(seed_b);
    let (out, proof) = kp_a.evaluate(&input);
    let result = verify(&kp_b.public_key_bytes(), &input, &out, &proof);
    assert!(
        result.is_err(),
        "verify accepted VRF output from a different key"
    );
}

// ----------------------------------------------------------------------------
// Property 6 — input mutation rejects.
// Binding to the input transcript means evaluating a different input
// produces an output that does not verify against the old one.
// ----------------------------------------------------------------------------
#[hegel::test]
fn vrf_input_mutation_rejects(tc: hegel::TestCase) {
    let seed = draw_seed(&tc);
    let input: Vec<u8> = tc.draw(generators::binary().min_size(1).max_size(64));
    let kp = VrfKeypair::from_seed(seed);
    let pk = kp.public_key_bytes();
    let (out, proof) = kp.evaluate(&input);

    let byte_idx = tc.draw(
        generators::integers::<usize>()
            .min_value(0)
            .max_value(input.len() - 1),
    );
    let bit_idx = tc.draw(generators::integers::<u8>().min_value(0).max_value(7));
    let mut mutated = input.clone();
    mutated[byte_idx] ^= 1_u8 << bit_idx;
    if mutated == input {
        return;
    }

    let result = verify(&pk, &mutated, &out, &proof);
    assert!(
        result.is_err(),
        "verify accepted VRF output against a mutated input"
    );
}

// ----------------------------------------------------------------------------
// Property 7 — weak empirical-uniformity check.
// Over N_JOBS *distinct* VRF-based winner selections with N_RUNNERS fixed
// runners, no runner wins catastrophically many jobs (bias check) and the
// winner set is non-degenerate (coverage check).
//
// This is a **weak** pointwise check; the actual fairness claim (Jain's
// index ≥ J_min over the distribution of churn and load) is B-stat and
// lives in `hypotheses/scheduling-fairness.md`.
//
// Hegel case count is reduced: VRF signing is ~16ms, and 5 runners × 30
// jobs × 100 default cases would take > 4 minutes. `test_cases = 5` keeps
// this test under ~15s while still exercising the property across distinct
// runner keys and input distributions.
// ----------------------------------------------------------------------------
#[hegel::test(test_cases = 5)]
fn vrf_winner_selection_not_degenerate(tc: hegel::TestCase) {
    const N_RUNNERS: usize = 5;
    const N_JOBS: usize = 30;

    let mut runners: Vec<VrfKeypair> = Vec::with_capacity(N_RUNNERS);
    for _ in 0..N_RUNNERS {
        runners.push(VrfKeypair::from_seed(draw_seed(&tc)));
    }

    // *Distinct* seeds — the uniformity claim is about the output
    // distribution over distinct inputs. Without `.unique(true)` Hegel
    // correctly shrinks to all-zero seeds, which are all the same input
    // and so deterministically produce one winner.
    let seeds: Vec<Vec<u8>> = tc.draw(
        generators::vecs(generators::binary().min_size(32).max_size(32))
            .unique(true)
            .min_size(N_JOBS)
            .max_size(N_JOBS),
    );

    let mut wins = vec![0_usize; N_RUNNERS];
    for seed_v in &seeds {
        let winner = runners
            .iter()
            .enumerate()
            .map(|(i, kp)| (i, kp.evaluate(seed_v).0))
            .min_by(|a, b| a.1.cmp(&b.1))
            .expect("nonempty runner set")
            .0;
        wins[winner] += 1;
    }

    let max_wins = *wins.iter().max().expect("nonempty");
    let distinct_winners = wins.iter().filter(|&&w| w > 0).count();

    // Expected mean is 6/30 per runner. `max_wins >= 24` is ~8σ above
    // the uniform expectation — functionally impossible under honest VRF.
    assert!(
        max_wins < 24,
        "max wins {} out of {} (runners: {:?})",
        max_wins,
        N_JOBS,
        wins
    );
    // At least 2 distinct winners in 30 uniform-ish draws is essentially
    // certain: P(1 winner across 30 draws) = 5 * (1/5)^30 ≈ 5e-21.
    assert!(
        distinct_winners >= 2,
        "only {} distinct winners in {} jobs (runners: {:?})",
        distinct_winners,
        N_JOBS,
        wins
    );
}
