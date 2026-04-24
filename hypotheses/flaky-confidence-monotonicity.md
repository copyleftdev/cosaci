---
id: flaky-confidence-monotonicity
source: SPEC.md §12.2a
class: A
status: passing
test: tests/flaky_confidence_monotonicity.rs
first_passing: 2026-04-24
note: "v0.1 scoring = disagreement_count / total_runs (identity). Monotone by construction. If v2 adopts Wilson score or Bayesian priors, this test catches any transformation that breaks monotonicity-for-fixed-total_runs."
---

# flaky-confidence-monotonicity

**Claim:** Flake confidence is a monotone non-decreasing function of runner disagreement count (for a fixed run count). More disagreement among independent runners on the same (commit, test) pair yields higher confidence the test is flaky.

**Property (pointwise universal):**
- For any two disagreement histories `h1`, `h2` for the same test over the same number of runs: if `disagreement_count(h1) ≥ disagreement_count(h2)`, then `flake_confidence(h1) ≥ flake_confidence(h2)`.
- **Zero-disagreement baseline:** `disagreement_count == 0 ⟹ flake_confidence == 0` (or a fixed low prior, documented by the spec).
- **Full-disagreement ceiling:** confidence saturates at a defined maximum (≤ 1.0 for probabilities).

**Test shape:** direct `#[hegel::test]`; Hegel draws two disagreement histories, assert monotonicity.

**Why pointwise, not B-stat:** this is the monotonicity *core* that `flaky-detection-recall` (B-stat) aggregates. Cheap, always-green regression signal; if this fails, no detection-recall claim can hold.

**Notes:** The exact scoring function (ratio, Wilson score, Beta posterior) is a primitive commitment; this card tests only that whichever function is chosen satisfies the monotonicity.
