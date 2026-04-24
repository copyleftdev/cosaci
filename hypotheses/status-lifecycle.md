---
id: status-lifecycle
source: SPEC.md §11.2
class: A
status: passing
test: tests/status_lifecycle.rs::status_machine_matches_dag
first_passing: 2026-04-24
---

# status-lifecycle

**Claim:** External (SCM-visible) status transitions form a DAG:
`pending → running → quorum-verifying → {success | failure}`.
No skipped transitions. No backward transitions. No state invented outside this set.

**Property (state-machine):**
- **Allowed transitions only:** attempting a transition not in the allowed edge set is an error.
- **No regress:** once `success` or `failure`, no further transitions.
- **No skips:** `pending → success` (skipping `running` and `quorum-verifying`) is rejected.
- **Every emitted status is in the set:** the set is closed under all external events.

**Test shape:** `#[hegel::state_machine]` with one rule per allowed transition and one rule `attempt_illegal_transition` that asserts rejection.

**Scope boundary:** this card tests the *external contract* to the SCM. Internal machinery (shard migration, vote collection) may have finer-grained states but must aggregate into exactly these four externally.

**Notes:** If CosaCI later adds `cancelled` or `stale` as external statuses, this card updates (the spec and the test together).
