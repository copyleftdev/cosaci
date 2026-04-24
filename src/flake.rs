//! Flaky-test detection scoring.
//!
//! Source: `SPEC.md` §12.2a / `hypotheses/flaky-confidence-monotonicity.md`
//! (class A). Pointwise monotonicity core of the B-stat flaky-detection-recall
//! claim (§12.2b). Kept deliberately shape-simple in v0.1 so the claim is
//! falsifiable by a concrete implementation, not a tautology: if later
//! versions adopt Wilson scoring or Bayesian priors, this test will catch
//! any transformation that breaks monotonicity for fixed `total_runs`.

/// Confidence in `[0.0, 1.0]` that a test is flaky, given the observed
/// disagreement count and total run count across independent runners.
///
/// - `disagreement_count == 0` → `0.0` (no evidence of flake).
/// - `disagreement_count == total_runs` (> 0) → `1.0` (unanimous flake).
/// - For fixed `total_runs`, confidence is monotone non-decreasing in
///   `disagreement_count`.
///
/// `total_runs == 0` returns `0.0` (no evidence, no confidence).
#[must_use]
pub fn flake_confidence(disagreement_count: u32, total_runs: u32) -> f64 {
    if total_runs == 0 {
        return 0.0;
    }
    f64::from(disagreement_count) / f64::from(total_runs)
}
