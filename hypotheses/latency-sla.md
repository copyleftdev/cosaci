---
id: latency-sla
source: SPEC.md §16
class: D
status: pending
---

# latency-sla

**Claim:** At public-infrastructure scale, p99 end-to-end job-validation latency is below a committed SLA (e.g., p99 < 90s for a 1-minute test job; p50 < 15s).

**Why class D:** latency-at-scale is a load-testing domain, not a Hegel-layer property. Concrete SLA numbers depend on: realistic traffic shape, realistic runner distribution, realistic network latency, real attestation-log anchoring frequency.

**What *can* be tested (elsewhere):**
- Per-stage latency budgets enforced as `cancel_after(Duration)` timeouts in code (Hegel can check that timeout fires correctly — that would be a distinct class-A card if we need it).
- Benchmark harness (`criterion`) on hot paths: VRF evaluation, signature verify, quorum aggregate, Merkle append.
- Load-testing harness against a staged fleet.

**Notes:** The committed SLA numbers themselves are a product decision and need stakeholder input before being hard-coded. Until numbers are committed, this card records only the *shape* of the claim.
