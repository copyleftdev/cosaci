---
id: replay-protection
source: SPEC.md §9.1
class: A
status: passing
tests:
  - tests/replay_protection.rs::replay_guard_matches_model
  - tests/bloom_fp_rate.rs
depends_on: "cosaci::clock::Clock trait ✓; cosaci::bloom::BloomFilter ✓ (hand-rolled)"
primitive_pick: "v0.1 ReplayGuard uses HashMap for the active-window index; scale-variant Bloom filter primitive lives in src/bloom.rs with validated FP-rate ≤ (1−exp(−kn/m))^k + tolerance. Swap is a future refactor — the FP-rate claim is proven for the primitive."
first_passing: 2026-04-24
bloom_fp_rate_closed: 2026-04-24
---

# replay-protection

**Claim:** Every message carries a `(nonce, timestamp)`. The coordinator accepts a message iff its `nonce` is not present in the active-window index and `|now - timestamp| ≤ TTL`. After TTL elapses from first acceptance, the nonce can be reused.

**Property (invariant under state-machine):**
- **No replay within window:** for any two accepted messages `m1, m2` with `m1.nonce == m2.nonce`, `|m1.accept_time - m2.accept_time| > TTL`.
- **Post-TTL reuse allowed:** a nonce that was accepted at `t0` is accepted again at `t > t0 + TTL`.
- **Expired-timestamp rejection:** a message whose `|now - timestamp| > TTL` is rejected regardless of nonce.
- **Bloom false-positive bound (scale sub-claim):** when the active-window index is a bloom filter (required at 10⁶-nonce scale), the false-positive rate is bounded by the configured `(m, k)` parameters; legitimate messages are rejected at rate ≤ `(1 - e^(-kn/m))^k`.

**Test shape:** `#[hegel::state_machine]` with rules `send_message`, `advance_clock`, with invariants. Clock is injectable.

**Bug-pattern watch:** clock skew across shards allowing a replay at one shard after expiry at another; bloom filter never resets; nonce collision with legitimate fresh messages.

**Notes:** The bloom-FP sub-claim may move to its own card once the bloom primitive is chosen. For now it is embedded here.
