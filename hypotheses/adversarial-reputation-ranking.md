---
id: adversarial-reputation-ranking
source: SPEC.md §8.3b
class: B-stat
status: passing
test: tests/adversarial_reputation_ranking.rs::reputation_ranks_adversaries_below_honest
depends_on: "rand 0.10 + rand_chacha 0.10 (ChaCha8Rng for seeded inner sampling)"
primitive_pick: "Seeded ChaCha8Rng inner loop with N_INNER=50; test_cases=15; honest-voter reliability=0.95; adversary strategy=random; honest-fraction bar=0.95"
first_passing: 2026-04-24
note: "First B-stat card — debuts the inner-sampling test shape per memory/feedback_statistical_vs_universal.md. Bar is deliberately loose (0.95) because under honest majority with random adversaries, the mean is essentially 1.0; bar protects against catastrophic regressions, not sub-percent fluctuations."
---

# adversarial-reputation-ranking

**Claim:** Under adversary rate `p ∈ [0, 1/3]`, reputation correctly ranks honest runners above adversaries with high probability. Specifically: the top-k reputation set contains ≥ `(1 - δ(p))` honest runners, for some spec-specified `δ(p)`.

**Property (B-stat):**
- Hegel draws distribution parameters: `p` (adversary rate), `N` (fleet size), history length `T`.
- Inner loop (N_inner = 500, seeded): synthesize `N` runners with `p·N` adversarial; simulate `T` quorum rounds where adversaries vote against majority with defined probability; compute reputation; observe top-k composition.
- Assert: mean fraction of honest runners in top-k ≥ threshold `τ(p)`.

**Why B-stat, not A:** "correctly ranks adversaries" is inherently averaged over adversarial strategies and noise. The *monotonicity core* of this claim is pulled out as `reputation-monotonicity` (class A).

**Test shape:** `#[hegel::test]` that draws distribution params; inside, use `mc::Rng` for inner sampling (avoids Hegel CBOR superlinear cost above N²≈1000 draws — prior memory `feedback_seed_driven_scale`).

**Scope:** `p ∈ [0, 1/3]` is the honest-majority regime. Beyond 1/3, the test that applies is `sybil-resistance` (system should fail safely to ESCALATE, not silently to PASS).

**Notes:** Choice of adversarial strategy (always-disagree, coordinated-minority, random-noise) is parameterized; each strategy gets a sub-test or Hegel draws it as an enum.
