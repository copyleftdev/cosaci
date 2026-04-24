---
id: scheduling-fairness
source: SPEC.md §7.1
class: B-stat
status: passing
test: tests/scheduling_fairness.rs::jains_index_meets_bar
depends_on: "sha2 as VRF-equivalent fairness oracle; rand_chacha"
primitive_pick: "SHA-256-based pick_winner stand-in for VRF (deterministic in (job_seed, runner_id); uniform over output space). VRF correctness itself is vrf-assignment-uniformity (Tier 1 ✓) — this card tests the resulting *distribution*."
first_passing: 2026-04-24
note: "Tests steady-state fairness without churn. Dynamic churn (joins/leaves mid-simulation) is a future refinement; the static-fleet Jain's index floor is the hardest part of the claim."
---

# scheduling-fairness

**Claim:** VRF-based assignment distributes jobs fairly across runners with similar capabilities, even under runner churn (join/leave). Jain's fairness index over job counts per runner ≥ `J_min` (e.g., 0.9) at steady state.

**Property (B-stat):**
- Hegel draws: churn rate `c`, load distribution parameters, capability distribution, time horizon `T`.
- Inner loop: simulate `T` time units of VRF assignment with runners joining/leaving per churn rate; count jobs per runner.
- Assert: mean Jain's index `J = (Σx_i)² / (N · Σx_i²)` over inner samples ≥ `J_min`.

**Why B-stat:** "fair under churn" is a statistical property. The pointwise core (VRF output is uniform given runner set) is `vrf-assignment-uniformity` (A).

**Test shape:** `#[hegel::test]`; seed-driven inner loop; Jain's index computed per inner sample.

**Scope:** Fairness across heterogeneous capabilities is harder (more-capable runners should do more work). This card restricts to *similar-capability* fleets. Heterogeneous fairness is a separate card if we ever need it.

**Notes:** `J_min = 0.9` is a starting target. If the test is flakier than expected, consider (a) raising `T` for longer averaging, (b) lowering `J_min`, but NOT (c) narrowing the churn rate draw — that would be the "narrow precondition" anti-pattern (see `feedback_statistical_vs_universal`).
