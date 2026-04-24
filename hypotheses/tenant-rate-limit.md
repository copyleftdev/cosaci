---
id: tenant-rate-limit
source: SPEC.md §13 (new, required at public scale)
class: A
status: passing
test: tests/tenant_rate_limit.rs::rate_limiter_matches_model
depends_on: "cosaci::clock::Clock trait ✓; hand-rolled token bucket"
primitive_pick: "classic token bucket (capacity C, refill rate r tokens/sec), per-tenant HashMap"
first_passing: 2026-04-24
note: "Distributed per-tenant limiting across coordinator shards is a separate future concern. v0.1 is single-node algebra."
---

# tenant-rate-limit

**Claim:** Per-tenant rate limiting uses a token bucket. Bucket has capacity `C` and refill rate `r` tokens/second. A request of cost `c` is accepted iff `tokens ≥ c`; accepted requests decrement `tokens`. Tokens refill proportionally to elapsed time, clipped at `C`.

**Property (pointwise + state-machine):**
- **Bounded state:** `tokens ∈ [0, C]` always.
- **Monotone refill:** advancing the clock without requests is monotone non-decreasing in `tokens`.
- **Fairness (equal config → equal steady-state throughput):** two tenants with identical `(C, r)` and identical request streams receive identical accept counts over a long window.
- **Isolation:** one tenant exhausting its bucket does not affect another tenant's bucket.
- **Cost-correctness:** a request of cost `c` accepted at time `t` with `tokens_before = T` leaves `tokens_after = T - c`.

**Test shape:** `#[hegel::state_machine]` with rules `request(tenant, cost)`, `advance_clock`. Invariants checked after each rule.

**Scope:** this tests *single-node* token-bucket algebra. Distributed rate limiting across shards is a harder claim (consensus on the bucket state) and would be a separate card if we ever need perfectly-synchronized per-tenant limits.

**Notes:** At public scale, sloppy-counting (probabilistic) rate limiting may be preferred over exact; if so, revisit with an FP-rate sub-claim.
