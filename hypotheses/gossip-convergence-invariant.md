---
id: gossip-convergence-invariant
source: SPEC.md §12.3
class: A
status: passing
test: tests/gossip_convergence_invariant.rs
depends_on: "hand-rolled LWW-register CRDT in src/gossip.rs"
primitive_pick: "LWW register keyed by u64 with (value, timestamp) entries; max-value tiebreak on equal timestamp"
first_passing: 2026-04-24
note: "Tests pure merge algebra + bounded-round convergence under interleaved writes and pairwise gossip. Propagation *time* is the B-stat gossip-propagation-time card in Tier 2."
---

# gossip-convergence-invariant

**Claim:** Given no new writes, repeated gossip rounds drive all non-faulty nodes to the same state in bounded time. The merge function is associative, commutative, and idempotent (CRDT-like) so concurrent updates reconcile without coordination.

**Property (state-machine):**
- **Eventual consistency:** after `R` rounds with no new writes (`R ≥ R_conv` where `R_conv` is a function of topology and fanout), `∀ pairs (i, j): state_i == state_j`.
- **Merge idempotency:** `merge(s, s) == s`.
- **Merge commutativity:** `merge(a, b) == merge(b, a)`.
- **Merge associativity:** `merge(merge(a, b), c) == merge(a, merge(b, c))`.
- **Monotone progress:** at each round, the set of node pairs in disagreement is non-increasing (under no new writes).

**Test shape:** `#[hegel::state_machine]` with rules `write(node, k, v)`, `gossip_round(node_a, node_b)`. Invariants after each rule; convergence is asserted by running rounds until quiescent and comparing final states.

**Scope:** This card tests convergence in the *absence of adversarial gossip* (no byzantine nodes corrupting state). Byzantine-tolerant gossip is outside scope; we rely on signed updates + reputation to bound that attack surface.

**Notes:** Propagation *time* (vs merely convergence) is `gossip-propagation-time` (B-stat).
