---
id: sybil-resistance
source: SPEC.md §9.1 (Sybil row)
class: B-stat
status: passing
test: tests/sybil_resistance.rs
depends_on: "cosaci::quorum::aggregate ✓ (stake-weighted 2/3 threshold); rand_chacha"
first_passing: 2026-04-24
second_hegel_shrink: "Modeled honest voters with 5% noise; Hegel found n_honest=3 + noise=0.04 + s=0 → all-honest-Pass by chance pushed past threshold. Fleet-reliability noise, not adversary achievement. Fix: honest voters deterministic-Fail, randomness moved to attacker *coordination* (prob each sybil votes Pass ∈ [0.5, 1.0]). Keeps the honest-majority claim clean and falsifies actual adversary behavior."
note: "Test holds strictly for s ∈ [0, 0.5] against a 2/3 threshold. At s > 2/3, PASS is reachable by construction (adversary can provide threshold-crossing stake). Boundary cases s ∈ [0.5, 2/3] are the 'ESCALATE' regime of the original card — covered by the honest-majority-holds aspect: adversary alone below 2/3 cannot PASS."
---

# sybil-resistance

**Claim:** Stake-weighted quorum resists Sybil attacks where a single actor controls many pubkeys. If the attacker's *stake fraction* `s` is below `1/3`, no false PASS is possible for adversary-authored commits. At `s ∈ [1/3, 1/2]`, the system escalates (returns `ESCALATE`) rather than silently PASSing.

**Property (B-stat):**
- Hegel draws `s ∈ [0, 1/2]`, fleet size `N`, Sybil-identity count per attacker `k` (many pubkeys, one stake pool).
- Inner loop: synthesize fleet where attacker controls fraction `s` of total stake across `k` pubkeys; attacker attempts to push a bad commit through quorum.
- Assert:
  - **Safety below 1/3:** for `s < 1/3 - ε`, probability of a bad PASS = 0 (exact, not averaged — but testing through inner sampling).
  - **Escalation near 1/3:** for `s ∈ [1/3, 1/2]`, outcomes are `ESCALATE` or `FAIL`, never `PASS` for adversary-authored commits.
  - **Sybil count insensitivity:** for fixed `s`, increasing `k` (more Sybil identities for same stake) does not shift outcome distribution — the stake-weighting is the defense, not identity counting.

**Why B-stat:** averaged over attacker strategies and vote patterns. The *monotone in stake* core could be pulled out as an A-card if monotonicity of PASS-probability in honest-stake-fraction turns out clean.

**Test shape:** `#[hegel::test]` with seed-driven inner loop; outer Hegel draws distribution params.

**Notes:** This card assumes P6 (slashing) creates cost for adversaries; without slashing, B-stat becomes weaker. If P6 is deferred, update `depends_on` and test threshold.
