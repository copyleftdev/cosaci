---
id: result-aggregation
source: SPEC.md §8.2
class: A
status: passing
tests:
  - tests/result_aggregation.rs::aggregator_lifecycle_matches_model
  - tests/aggregator_retry_bound.rs
first_passing: 2026-04-24
max_retries_closed: 2026-04-24
primitive_pick: "Aggregator::with_max_retries(threshold, stake, max_retries) + trigger_aggregation() increments retry counter on Retry outcomes; forces Escalate once counter exceeds max_retries. receive_vote does NOT consume retry budget (fresh evidence ≠ retry)."
note: "Closed former max-retries † deferral — see tests/aggregator_retry_bound.rs for the three retry-bound properties (exact-boundary, default-unbounded, receive_vote-doesn't-increment)."
---

# result-aggregation

**Claim:** Aggregation is a state machine over vote arrivals and timeouts. Lifecycle: `Pending → {Pass | Fail | Retry | Escalate}`. `Pass` and `Fail` are terminal-success / terminal-failure. `Retry` is transient and can transition to any of the four. `Escalate` is terminal-human.

**Property (state-machine):**
- **Terminal stability:** once in `Pass`, never leaves `Pass`. Once in `Fail`, never leaves `Fail`. Once in `Escalate`, never leaves.
- **Retry is bounded:** the number of `Retry → Retry` cycles is ≤ `max_retries`; exceeding it forces `Escalate`.
- **Timeout forces terminal:** a timeout in `Pending` transitions to `Escalate` (never silently drops).
- **Vote-count monotone:** the count of counted votes is non-decreasing across state transitions.
- **Outcome consistency with §8.1:** on every quorum check, outcome equals `quorum-math`'s pure `aggregate()`.

**Test shape:** `#[hegel::state_machine]` with rules `receive_vote`, `trigger_aggregation`, `timeout`, `retry`. Invariants after each rule.

**Notes:** This card overlaps with `quorum-math` intentionally — `quorum-math` tests the pure function; this card tests the lifecycle wrapper and its consistency with the pure function. Divergence between them is a bug.
