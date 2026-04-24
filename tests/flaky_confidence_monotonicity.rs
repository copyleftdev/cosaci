//! Property-based tests for `cosaci::flake::flake_confidence`.
//!
//! Encodes the falsifiable claims of `hypotheses/flaky-confidence-monotonicity.md`
//! (SPEC.md §12.2a, class A). This is the pointwise core of the B-stat
//! detection-recall claim in `hypotheses/flaky-detection-recall.md`.

use cosaci::flake::flake_confidence;
use hegel::generators;

// ----------------------------------------------------------------------------
// Property 1 — monotone in disagreement_count for fixed total_runs.
// ----------------------------------------------------------------------------
#[hegel::test]
fn monotone_in_disagreement(tc: hegel::TestCase) {
    let total = tc.draw(generators::integers::<u32>().min_value(1).max_value(1_000));
    let d1 = tc.draw(generators::integers::<u32>().min_value(0).max_value(total));
    let d2 = tc.draw(generators::integers::<u32>().min_value(0).max_value(total));
    let c1 = flake_confidence(d1, total);
    let c2 = flake_confidence(d2, total);
    if d1 >= d2 {
        assert!(
            c1 >= c2,
            "monotonicity broken: d1={} d2={} total={} c1={} c2={}",
            d1,
            d2,
            total,
            c1,
            c2
        );
    }
}

// ----------------------------------------------------------------------------
// Property 2 — bounded in [0.0, 1.0].
// ----------------------------------------------------------------------------
#[hegel::test]
fn confidence_is_bounded(tc: hegel::TestCase) {
    let total = tc.draw(generators::integers::<u32>().min_value(0).max_value(1_000));
    let d = tc.draw(
        generators::integers::<u32>()
            .min_value(0)
            .max_value(total.max(1)),
    );
    let d = d.min(total); // guard when total == 0
    let c = flake_confidence(d, total);
    assert!(c >= 0.0, "confidence below 0: {}", c);
    assert!(c <= 1.0, "confidence above 1: {}", c);
}

// ----------------------------------------------------------------------------
// Property 3 — zero-disagreement baseline: confidence is exactly 0.0.
// ----------------------------------------------------------------------------
#[hegel::test]
fn zero_disagreement_is_zero_confidence(tc: hegel::TestCase) {
    let total = tc.draw(generators::integers::<u32>().min_value(1).max_value(1_000));
    let c = flake_confidence(0, total);
    assert!(
        c.abs() < f64::EPSILON,
        "zero-disagreement produced confidence {}",
        c
    );
}

// ----------------------------------------------------------------------------
// Property 4 — full-disagreement ceiling: confidence saturates at 1.0.
// ----------------------------------------------------------------------------
#[hegel::test]
fn full_disagreement_is_one(tc: hegel::TestCase) {
    let total = tc.draw(generators::integers::<u32>().min_value(1).max_value(1_000));
    let c = flake_confidence(total, total);
    assert!(
        (c - 1.0).abs() < f64::EPSILON,
        "full-disagreement produced confidence {}",
        c
    );
}

// ----------------------------------------------------------------------------
// Property 5 — zero total runs: no evidence, no confidence.
// Deterministic regardless of Hegel draws.
// ----------------------------------------------------------------------------
#[hegel::test]
fn zero_total_runs_is_zero_confidence(_tc: hegel::TestCase) {
    assert!(flake_confidence(0, 0).abs() < f64::EPSILON);
}
