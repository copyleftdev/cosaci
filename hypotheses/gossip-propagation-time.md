---
id: gossip-propagation-time
source: SPEC.md §12.3
class: B-stat
status: passing
test: tests/gossip_propagation_time.rs::gossip_propagates_within_log_bound
depends_on: "hand-rolled round-based push-gossip simulator; rand_chacha"
primitive_pick: "Push-gossip with fanout f per round; bar = 4·log_f(N) on mean rounds-to-convergence"
first_passing: 2026-04-24
---

# gossip-propagation-time

**Claim:** With fanout `f` and round interval `Δ`, a write at any node propagates to all non-faulty nodes in expected time `O(log_f N) · Δ`, where `N` is the cluster size.

**Property (B-stat):**
- Hegel draws `N`, fanout `f ∈ [2, 8]`, round interval `Δ`, fault rate `φ ∈ [0, 0.1]`.
- Inner loop: simulate gossip from a seed write; measure rounds until all non-faulty nodes have the write; repeat for many trials.
- Assert: mean propagation rounds ≤ `C · log_f N` for some constant `C` (documented), within variance bound.

**Why B-stat:** propagation time is a statistical property over network schedules and fault occurrences. Convergence-at-all is `gossip-convergence-invariant` (A).

**Test shape:** `#[hegel::test]`; seeded inner simulation; measure time-to-convergence per trial.

**Notes:** Real network latency distributions are heavy-tailed; the test uses an abstract round-based simulator. Real propagation is `real-partition-recovery` (class C). Constant `C` and tolerable variance are spec-committed numbers; record them explicitly in the card when the test is written.
