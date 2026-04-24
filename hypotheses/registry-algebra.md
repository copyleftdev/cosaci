---
id: registry-algebra
source: SPEC.md §5.2a
class: A
status: passing
test: tests/registry_algebra.rs::registry_matches_hashmap_model
first_passing: 2026-04-24
note: "First #[hegel::state_machine] card. Validates stateful-testing API path of hegeltest 0.8.0 for all downstream state-machine cards."
---

# registry-algebra

**Claim:** The runner registry is a map `RunnerId → (pubkey, stake, capabilities)`. `register` adds a new entry; `deregister` removes it; `lookup` returns the current state; a lease can only be issued to a currently-registered runner. `deregister` is idempotent (calling twice = calling once).

**Property (model-based):** For any sequence of operations drawn by Hegel over `{register, deregister, lookup, request_lease}`, the registry state equals a `HashMap` oracle after every step. Additionally:
- `request_lease(r)` succeeds iff `r` is in the current map.
- `deregister(r); deregister(r)` state-equivalent to `deregister(r)`.
- `register(r, v1); register(r, v2)` overwrites (last-write-wins).

**Test shape:** `#[hegel::state_machine]` with rules `register`, `deregister`, `lookup`, `request_lease` and invariant `subject == model`.

**Notes:** TLS / pubkey-authenticity is out of scope here (see `mtls-enforcement`, class C). Stake weighting is tested in `quorum-math`; here stake is just a field.
