---
id: latency-sla
source: SPEC.md §16
class: D
status: passing
bench: benches/hot_paths.rs
depends_on: "criterion 0.7"
primitive_pick: "Criterion micro-benchmarks on hot paths. Concrete SLA thresholds (e.g., 'p99 end-to-end job-validation < 90s') are a product-committed value, not a derivable one — but per-operation baselines serve as a regression gate."
first_passing: 2026-04-24
baseline_ns:
  "quorum/aggregate-5x1": 149
  "attestation/canonicalize": 1560
  "attestation/hash": 1843
  "ed25519/sign": 15400
  "ed25519/verify": 33100
  "vrf/evaluate": 95900
  "vrf/verify": 84000
  "verifier/compute_root-16": 2740
  "verifier/verify_inclusion-16": 1226
  "gossip/merge-32x32": 812
note: "Baseline measured on the dev host 2026-04-24 (wall-clock nanoseconds, median). Run `cargo bench --bench hot_paths` to re-baseline. SLA thresholds are not asserted here — `assert_ms < T` checks would be flaky across hardware. This card's closure is the existence of the benchmark harness + a recorded baseline, so regressions surface when numbers change materially."
sub_claim_deferred: "End-to-end latency under realistic public-infra-scale traffic. Requires a staged fleet + load generator; not runnable inside cargo. Micro-benchmarks above give per-op shape, which feeds into an end-to-end latency budget when that harness gets built."
---

# latency-sla

**Claim:** At public-infrastructure scale, p99 end-to-end job-validation latency is below a committed SLA (e.g., p99 < 90s for a 1-minute test job; p50 < 15s).

**Why class D:** latency-at-scale is a load-testing domain, not a Hegel-layer property. Concrete SLA numbers depend on: realistic traffic shape, realistic runner distribution, realistic network latency, real attestation-log anchoring frequency.

**What *can* be tested (elsewhere):**
- Per-stage latency budgets enforced as `cancel_after(Duration)` timeouts in code (Hegel can check that timeout fires correctly — that would be a distinct class-A card if we need it).
- Benchmark harness (`criterion`) on hot paths: VRF evaluation, signature verify, quorum aggregate, Merkle append.
- Load-testing harness against a staged fleet.

**Notes:** The committed SLA numbers themselves are a product decision and need stakeholder input before being hard-coded. Until numbers are committed, this card records only the *shape* of the claim.
