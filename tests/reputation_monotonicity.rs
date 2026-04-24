//! Property-based tests for `cosaci::reputation::{agreement_rate, reputation}`.
//!
//! Encodes the falsifiable claims of `hypotheses/reputation-monotonicity.md`
//! (SPEC.md §8.3a, class A). Monotonicity is the pointwise core of the
//! adversarial-ranking B-stat claim (§8.3b) — if this card is ever
//! falsified, §8.3b's statistical guarantees are structurally undermined.

use cosaci::reputation::{AgreementOutcome, INITIAL_REPUTATION, agreement_rate, reputation};
use hegel::{TestCase, generators};

fn draw_outcome(tc: &TestCase) -> AgreementOutcome {
    if tc.draw(generators::booleans()) {
        AgreementOutcome::Agree
    } else {
        AgreementOutcome::Disagree
    }
}

fn draw_history(tc: &TestCase) -> Vec<AgreementOutcome> {
    let n = tc.draw(generators::integers::<usize>().min_value(0).max_value(100));
    let mut h = Vec::with_capacity(n);
    for _ in 0..n {
        h.push(draw_outcome(tc));
    }
    h
}

// ----------------------------------------------------------------------------
// Property 1 — monotone in agreement rate.
// For any two histories, if h1 has at least as high an agreement rate as h2,
// then reputation(h1) >= reputation(h2).
// ----------------------------------------------------------------------------
#[hegel::test]
fn reputation_monotone_in_agreement_rate(tc: hegel::TestCase) {
    let h1 = draw_history(&tc);
    let h2 = draw_history(&tc);
    let a1 = agreement_rate(&h1);
    let a2 = agreement_rate(&h2);
    if a1 >= a2 {
        assert!(
            reputation(&h1) >= reputation(&h2),
            "monotonicity violated: a1={} a2={} rep1={} rep2={}",
            a1,
            a2,
            reputation(&h1),
            reputation(&h2)
        );
    }
}

// ----------------------------------------------------------------------------
// Property 2 — reputation is bounded in [0, 1].
// ----------------------------------------------------------------------------
#[hegel::test]
fn reputation_is_bounded(tc: hegel::TestCase) {
    let h = draw_history(&tc);
    let r = reputation(&h);
    assert!(r >= 0.0, "reputation below 0: {}", r);
    assert!(r <= 1.0, "reputation above 1: {}", r);
}

// ----------------------------------------------------------------------------
// Property 3 — empty-history baseline is the documented INITIAL_REPUTATION.
// Deterministic given the constant; Hegel draws nothing relevant but the
// test still runs through the shrinking engine.
// ----------------------------------------------------------------------------
#[hegel::test]
fn reputation_of_empty_history_is_initial(_tc: hegel::TestCase) {
    assert!(
        (reputation(&[]) - INITIAL_REPUTATION).abs() < f64::EPSILON,
        "empty-history reputation diverged from INITIAL_REPUTATION"
    );
}

// ----------------------------------------------------------------------------
// Property 4 — all-agree history saturates at 1.0.
// ----------------------------------------------------------------------------
#[hegel::test]
fn reputation_of_all_agree_is_one(tc: hegel::TestCase) {
    let n = tc.draw(generators::integers::<usize>().min_value(1).max_value(100));
    let h = vec![AgreementOutcome::Agree; n];
    let r = reputation(&h);
    assert!(
        (r - 1.0).abs() < f64::EPSILON,
        "all-agree reputation was {} (expected 1.0)",
        r
    );
}

// ----------------------------------------------------------------------------
// Property 5 — all-disagree history bottoms out at 0.0.
// ----------------------------------------------------------------------------
#[hegel::test]
fn reputation_of_all_disagree_is_zero(tc: hegel::TestCase) {
    let n = tc.draw(generators::integers::<usize>().min_value(1).max_value(100));
    let h = vec![AgreementOutcome::Disagree; n];
    let r = reputation(&h);
    assert!(
        r.abs() < f64::EPSILON,
        "all-disagree reputation was {} (expected 0.0)",
        r
    );
}
