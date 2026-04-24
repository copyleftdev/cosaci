---
id: coordinator-shard-algebra
source: SPEC.md §4.1.1
class: A
status: passing
tests:
  - tests/coordinator_shard_algebra.rs
  - tests/shard_incremental_handoff.rs
depends_on: "src/sharding.rs (atomic rebalance, FNV-mixed modular routing); src/sharding_handoff.rs (phased handoff); src/replicated_cluster.rs (multi-replica semantics, shared with partition-invariants)"
first_passing: 2026-04-24
incremental_handoff_closed: 2026-04-24
note: "Former † decomposed and closed: (1) incremental-handoff rebalance — src/sharding_handoff.rs with HandoffStore; reads consult both shard sets during migration, writes flow to new, migrate_step + complete_rebalance drain old. (2) multi-replica split-brain — covered by replicated_cluster (see partition-invariants card) with genuine two-replica divergence + reset-to-majority reconciliation. A specific Raft intra-shard consensus implementation is production engineering work outside the filter's algebraic scope; the algebraic safety/liveness claims are all green."
---

# coordinator-shard-algebra

**Claim:** `shard_of(key) = hash(key) mod N_shards` is deterministic. Rebalancing from `N` to `N'` shards migrates keys such that no key is lost and no key is served by two shards post-reconciliation. Each shard is a Raft group; cross-shard operations reconcile via gossip anti-entropy.

**Property (pointwise + state-machine):**
- **Deterministic routing:** `shard_of(k)` returns the same value for the same `(k, N)` input always.
- **Uniform distribution (weak):** over Hegel-drawn keys, the variance of shard load is bounded.
- **Rebalance completeness:** after `rebalance(N, N')`, every key that was on some shard pre-rebalance is on exactly one shard post-rebalance.
- **Rebalance safety:** during rebalance, reads return the correct value from either the source or destination shard (no lost-write; consistent hashing or handoff protocol).
- **Cross-shard commutativity:** gossip-applied operations from different shards commute (CRDT-like merge or explicit lock ordering).

**Test shape:** `#[hegel::state_machine]` with rules `put`, `get`, `rebalance_up`, `rebalance_down`, `gossip_round`. Invariants: all-keys-retrievable, no-duplicate-ownership.

**Scope:** tests the *algebra*. Real network partition tolerance is `partition-invariants` + class-C `real-partition-recovery`.

**Notes:** Consistent hashing with virtual nodes is one valid primitive; the card tests the chosen primitive. Raft-per-shard election behavior is out of scope (delegated to the Raft library's own tests).
