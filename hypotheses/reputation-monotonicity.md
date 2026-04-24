---
id: reputation-monotonicity
source: SPEC.md §8.3a
class: A
status: passing
test: tests/reputation_monotonicity.rs
first_passing: 2026-04-24
note: "v0.1 implementation is identity over agreement_rate — monotone by construction. When §8.3b adversarial-ranking is implemented with Wilson scoring or time decay, ensure the transformation preserves monotonicity or this card's claim narrows to 'for fixed history length'."
---

# reputation-monotonicity

**Claim:** A runner's reputation score is a monotone non-decreasing function of its historical agreement rate with quorum outcomes. If `agreement_rate(r1) ≥ agreement_rate(r2)`, then `reputation(r1) ≥ reputation(r2)`.

**Property (pointwise universal):**
- Hegel draws two agreement histories `h1`, `h2` for two runners.
- Compute `a1 = agreement_rate(h1)`, `a2 = agreement_rate(h2)`.
- Assert `a1 ≥ a2 ⟹ reputation(h1) ≥ reputation(h2)`.

**Test shape:** direct `#[hegel::test]`, no state machine needed.

**Why pointwise and not B-stat:** this is the monotonicity *core* that the B-stat claim `adversarial-reputation-ranking` (§8.3b) aggregates. Keeping this A-class gives a cheap regression signal; the expensive B-stat only has to demonstrate that the ranking *under adversarial load* exceeds a threshold, not that ranking is sane at all.

**Notes:** Agreement-rate aggregation must handle empty history (by spec: reputation of a new runner is a fixed `initial_reputation`). Hegel will find the empty-history case; the card must state the tie-breaking rule explicitly.
