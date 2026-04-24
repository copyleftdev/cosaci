---
id: partition-invariants
source: SPEC.md §12.3
class: A
status: passing
tests:
  - tests/partition_invariants.rs::cluster_gating_holds_under_partitions
  - tests/replicated_cluster_split_brain.rs
depends_on: "cosaci::clock::Clock ✓; cosaci::partition::Cluster (gate model) ✓; cosaci::replicated_cluster::TwoReplicaCluster (two-replica split-brain model) ✓"
primitive_pick: "Two complementary models: (1) single-state + gate — rejects minority writes; (2) two-replica + reset-to-majority reconciliation — permits split-brain during partition, resolves on heal."
first_passing: 2026-04-24
split_brain_closed: 2026-04-24
note: "Closed former multi-replica † deferral. Two-replica model in src/replicated_cluster.rs exercises: (a) Connected-mode propagation, (b) Partitioned-mode divergence, (c) Heal-time reconciliation via minority reset. Production Raft-per-shard is orthogonal; the claims this card tests are protocol-level."
---

# partition-invariants

**Claim:** Under arbitrary network partition and heal sequences, the "at most one active lease per `job_id`" invariant (from `lease-lifecycle`) continues to hold. No split-brain scenario issues two concurrent leases for the same job on different sides of a partition.

**Property (state-machine under partition):**
- **No-split-brain:** at every step, `|{l : l.active && l.job_id == J}| ≤ 1` globally (summed across partitions) for every `J`.
- **Partition-confined issuance:** a shard isolated from its Raft majority does not issue new leases for jobs it owned.
- **Heal convergence:** after partition heals, gossip reconciliation completes in bounded rounds (see `gossip-convergence-invariant`).
- **No phantom completions:** a completed-but-unreplicated result on the minority side is either re-executed post-heal or its completion is promoted to majority-visible (no silent drops).

**Test shape:** `#[hegel::state_machine]` with rules for `acquire`, `complete`, `partition(a, b)`, `heal`, `advance_clock`. Partition model is a test double that drops messages between groups.

**Relation:** This card extends `lease-lifecycle` under network failure. The single-node lease lifecycle must pass before this card is meaningful.

**Scope:** Tests invariants under *modeled* partitions. Real network partition recovery (TCP resets, asymmetric netem, clock-skew correlated failures) is `real-partition-recovery` (class C).
