---
id: lease-lifecycle
source: SPEC.md §5.3 + §7.2
class: A
status: passing
test: tests/lease_lifecycle.rs::lease_manager_matches_model
depends_on: "cosaci::lease::Clock trait (injected)"
first_passing: 2026-04-24
note: "Introduces the Clock trait pattern (impl on Cloneable wrapper around Rc<Cell<u64>>). Reused by replay-protection and partition-invariants cards."
---

# lease-lifecycle

**Claim:** Leases are time-bounded tokens that pair `(job_id, runner_id, lease_id)`. Rules: `acquire`, `complete`, `expire` (on TTL), `reassign` (after expire or explicit revoke). At most one active lease per `job_id` at any time. Execution under a lease is idempotent.

**Property (state-machine):**
- **Uniqueness invariant:** at every step, `|{l : l.active && l.job_id == J}| ≤ 1` for every job `J`.
- **TTL monotonicity:** advancing the virtual clock past `lease.acquired_at + TTL` transitions the lease to `expired` deterministically.
- **Reassignment yields fresh id:** `reassign(J)` after `expire(l)` produces a new `lease_id`, same `job_id`.
- **Idempotent completion:** `complete(l)` applied twice is identical to applying it once.
- **No late completion:** `complete(l)` on an already-expired lease is a no-op (not a revival).

**Test shape:** `#[hegel::state_machine]` with rules `acquire`, `complete`, `expire`, `advance_clock`, `reassign`. Invariant checks uniqueness after each rule. Clock is a test double.

**Notes:** This card does not test the real wall-clock; it tests the state machine under an injectable clock. Actual OS timer behavior is out of scope.
