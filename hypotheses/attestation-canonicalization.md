---
id: attestation-canonicalization
source: SPEC.md §10.2
class: A
status: passing
test: tests/attestation_canonicalization.rs
depends_on: "ciborium 0.2 (CBOR) + sha2 0.11 + serde-big-array 0.5"
primitive_pick: "CBOR via ciborium; struct-as-map with declaration-order fields; SHA-256 digest"
first_passing: 2026-04-24
---

# attestation-canonicalization

**Claim:** `hash(serialize(a))` is identical across every serialization of the same semantic content. This implies: deterministic field ordering, deterministic map key ordering, no trailing whitespace, canonical float encoding, canonical integer encoding.

**Property (pointwise, load-bearing):**
- **Hash stability:** for two attestations `a1 == a2` (structurally), `hash(serialize(a1)) == hash(serialize(a2))`.
- **Key-order invariance:** if the format has maps, permuting insertion order before serialize yields identical bytes.
- **Idempotent re-encoding:** `serialize(deserialize(serialize(a))) == serialize(a)` at the byte level.
- **No ambient state:** locale, timezone, or environment variable changes do not alter serialization.

**Test shape:** `#[hegel::test]` draws an attestation, builds a second attestation by constructing its fields in a different order (HashMap insertion order / struct field reassignment), asserts byte-equal serializations and equal hashes.

**Why this is load-bearing:** the Merkle log (`merkle-log-append-only`), replay-protection nonces, tamper-rejection verification, and every external trust claim downstream assume the hash of an attestation is a stable identity. If this card fails, the trust chain is theater.

**Format candidates:** RFC 8785 (JSON Canonicalization Scheme / JCS), DAG-CBOR, `serde_canonical`. The choice is a primitive commitment; the card tests the chosen primitive.

**Bug-pattern watch:** HashMap iteration order (Rust's is randomized by default), NaN float canonicalization, negative-zero, integer-vs-float ambiguity in JSON.
