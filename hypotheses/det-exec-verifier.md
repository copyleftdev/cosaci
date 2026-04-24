---
id: det-exec-verifier
source: SPEC.md §6.1a
class: A
status: passing
test: tests/det_exec_verifier.rs
depends_on: "rs_merkle 1.5 (binary Merkle over SHA-256)"
primitive_pick: "binary Merkle via rs_merkle, leaves sorted canonically before tree construction"
first_passing: 2026-04-24
note: "The append-only log (Tier 1, merkle-log-append-only) will use its own primitive (MMR) — the two serve different workloads and are allowed to diverge."
---

# det-exec-verifier

**Claim:** The execution verifier combines `(env_hash, cmd_hash, output_hash, artifact_hashes...)` into a canonical Merkle root. The root is stable under any canonical leaf ordering (sorted), inclusion proofs verify, and recomputing the root from leaves yields the same value.

**Property (pointwise):**
- **Order-insensitivity under canonical sort:** permuting the input leaves before the canonical sort yields the same root.
- **Inclusion-proof soundness:** for any leaf `l` in the set, the generated inclusion proof verifies against the root.
- **Inclusion-proof non-forgeability:** no valid proof exists for a leaf not in the set (Hegel tries forgeries).
- **Root determinism:** two calls with the same leaf set produce bitwise-identical roots.
- **Empty-set root defined:** the root of the empty set is a specified sentinel (not random, not panic).

**Test shape:** Hegel draws `Vec<[u8; 32]>` leaf sets; construct tree; assert properties. For non-forgeability, Hegel draws a `leaf` not in the set and attempts to construct a proof — must fail.

**Scope boundary:** this is the *verifier algebra*. Whether two real runners produce the same output bytes under the same environment is `real-runtime-determinism` (class C).

**Notes:** Choice of Merkle construction (binary, Merkle Mountain Range, MST) is a primitive commitment. MMR favors append-only log workloads (see `merkle-log-append-only`).
