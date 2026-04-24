---
id: flaky-detection-recall
source: SPEC.md §12.2b
class: B-stat
status: passing
test: tests/flaky_detection_recall.rs::recall_meets_bar_under_injected_flakiness
depends_on: "cosaci::flake::flake_confidence ✓; rand_chacha"
primitive_pick: "Detection rule: any non-zero flake_confidence flags flaky. Bar: mean recall ≥ 0.55 across 50 inner samples. K ∈ {3, 5, 7, 10}; p ∈ [0.10, 0.50]; T ∈ [50, 200]."
first_passing: 2026-04-24
---

# flaky-detection-recall

**Claim:** Flaky-test detection recall ≥ `r(p)` at injected flakiness rate `p`. Concretely: when a fraction `p` of (commit, test) pairs are injected to be flaky, the detector identifies ≥ `r(p)` fraction of them as flaky within `K` runs.

**Property (B-stat):**
- Hegel draws `p ∈ [0, 0.5]`, run count `K ∈ {3, 5, 7, 10}`, total test count `T`.
- Inner loop: synthesize `T` tests, mark `p·T` as truly flaky; simulate `K` runs per test across `N` runners; apply detector; compare to ground truth.
- Assert: mean recall over inner samples ≥ `r(p, K)`.
- Precision target is *not* asserted in this card (is a separate B-stat if we care) — recall-first matches the spec's "detect flakes".

**Why B-stat:** "recall ≥ r" is a population-level claim over a distribution of flakiness. Monotone cores: `flaky-confidence-monotonicity` (A) and "more runs → higher recall at fixed flake rate" (could become its own A-card).

**Test shape:** `#[hegel::test]` draws distribution params; seeded inner loop via `mc::Rng`.

**Notes:** `r(p, K)` must be documented explicitly in the card with concrete numbers (e.g., `r(0.1, 5) ≥ 0.9`). Missing numbers = unfalsifiable claim. Recommend starting conservative and tightening as the detector improves.
