---
id: collusion-probability
source: SPEC.md §7.1 + §9.1
class: B-stat
status: passing
test: tests/collusion_probability.rs::empirical_collusion_rate_within_bound
depends_on: "sha2 as VRF-equivalent selection oracle; rand_chacha"
primitive_pick: "SHA-256 top-k committee selection (lex-min of SHA-256(seed||runner_id)); theoretical bound 1/C(N,k); empirical bar = bound + 0.015 additive tolerance"
first_passing: 2026-04-24
---

# collusion-probability

**Claim:** The probability that `k` specific colluding runners are all assigned to the same job is bounded by a function of `k` and fleet size `N`, and approaches `k! / N^(k-1)` for VRF-based assignment selecting `k` runners from `N` uniformly at random without replacement.

**Property (B-stat):**
- Hegel draws `k ∈ [2, 7]`, `N ∈ [k, 10_000]`, job count `J`.
- Inner loop: for each of `J` jobs, pick `k` runners via VRF from fleet of `N`; check whether a specific pre-chosen colluding set of `k` runners all appeared.
- Assert: empirical collusion rate ≤ theoretical bound `k! · binom(N-k, 0) / binom(N, k) = k! / (N · (N-1) · ... · (N-k+1))`, within statistical tolerance.

**Why B-stat:** probability bound over a distribution of job seeds. The *determinism and unpredictability* of a single VRF output is in `vrf-assignment-uniformity` (A); this card tests the aggregate bound over many jobs.

**Test shape:** `#[hegel::test]`; seeded inner loop; compare empirical rate to theoretical bound.

**Notes:** Colluders can try to time their `join(runner)` calls to increase collision probability. Whether that attack exists depends on the VRF seed generation — if the seed is a commit hash posted before runner registration, this attack is mitigated. Document seed source as a primitive commitment.
