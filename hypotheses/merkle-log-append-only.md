---
id: merkle-log-append-only
source: SPEC.md §10.2
class: A
status: passing
tests:
  - tests/merkle_log_append_only.rs
  - tests/merkle_log_mmr_peaks.rs
depends_on: "rs_merkle 1.5 (prefix-recomputed binary Merkle); peak_heights + peak_hashes MMR decomposition"
primitive_pick: "Binary Merkle over entry prefix for root / proof, PLUS MMR peak decomposition (peak_heights(n) + MerkleLog::peak_hashes(n)) for structural peak-stability guarantees. Peak computation is on-demand in v0.1; production scale would add peak caching, which changes performance but not the algebraic properties tested here."
first_passing: 2026-04-24
mmr_structure_closed: 2026-04-24
note: "Former MMR † closed by adding peak decomposition API + 6 structural tests: peak count matches popcount, peak heights are descending bit positions, peak hashes deterministic, first peak stable across extensions, power-of-2 single-peak case equals root. The load-bearing claim — *once a peak forms, its hash never changes* — is captured by first_peak_is_stable_across_extensions. Performance caching is an implementation optimization with no further test surface."
---

# merkle-log-append-only

**Claim:** The attestation log is append-only. `append(entry)` is the only state-mutating operation. Every past entry remains retrievable with a valid inclusion proof. Periodic root anchoring (every N seconds) binds the log to a public bulletin; any rewrite of history breaks every anchored root.

**Property (state-machine):**
- **Append-only invariant:** after any sequence of appends, every previously-appended entry is still retrievable at its original index.
- **Root monotonicity:** the root after `n` appends is a function of the first `n` entries only; appending entry `n+1` produces a new root but does not alter the root at index `n`.
- **Inclusion-proof persistence:** a proof generated at time `t` remains valid against any anchored root that was current at or after `t`, even after many later appends.
- **Rewrite detection:** attempting to mutate any prior entry and recompute the root yields a root that does not match any anchored bulletin value.
- **No deletion:** there is no API to remove or overwrite an entry.

**Test shape:** `#[hegel::state_machine]` with rules `append`, `anchor_root`, `verify_inclusion`, `attempt_rewrite` (last must fail detection).

**Scope:** This card tests the log algebra. Whether the bulletin itself is tamper-evident (on-chain, signed timestamp authority, signed S3 object) is a primitive commitment tested separately at integration time.

**Notes:** Merkle Mountain Range (MMR) suits append-only better than balanced binary Merkle trees — old proofs remain valid without recomputation.
