---
id: survives-adversarial-execution
source: SPEC.md §16 (Key Insight)
class: D
status: pending
---

# survives-adversarial-execution

**Claim (meta):** A commit that passes CosaCI has survived adversarial execution: stake-weighted quorum agreed on an identical, verifier-approved, canonically-attested result, produced under VRF-assigned runners with Merkle-anchored provenance.

**Why class D:** this is the aggregate trust claim. It cannot be independently tested; it is the *conjunction* of all lower-tier claims holding simultaneously.

**Composition (what has to be green for this card to be considered corroborated):**
- All Tier 0 A-class cards passing: `registry-algebra`, `capability-match`, `lease-lifecycle`, `quorum-math`, `result-aggregation`, `reputation-monotonicity`, `replay-protection`, `tamper-rejection`, `attestation-roundtrip`, `attestation-canonicalization`, `status-lifecycle`, `det-exec-verifier`.
- All Tier 1 A-class cards passing: `coordinator-shard-algebra`, `vrf-assignment-uniformity`, `merkle-log-append-only`, `tenant-rate-limit`, `partition-invariants`, `confidentiality-algebra`, `flaky-confidence-monotonicity`, `gossip-convergence-invariant`.
- All Tier 2 B-stat cards within tolerance: `adversarial-reputation-ranking`, `sybil-resistance`, `flaky-detection-recall`, `scheduling-fairness`, `collusion-probability`, `gossip-propagation-time`.
- Tier 3 C-class cards have real-harness validation: `real-runtime-determinism`, `mtls-enforcement`, `real-partition-recovery`, `tee-attestation` (the last may remain blocked indefinitely in v1).

**Notes:** A CI job that computes the state of this card (`all green`? `which falsified`?) is a valuable artifact — it becomes the "is CosaCI itself trustworthy right now" dashboard. That build-status aggregator can be implemented once individual cards start passing.
