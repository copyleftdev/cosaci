---
id: attestation-roundtrip
source: SPEC.md §10.1
class: A
status: passing
test: tests/attestation_canonicalization.rs::roundtrip_equality
depends_on: "serde + ciborium"
note: "Subsumed by attestation-canonicalization test file — the round-trip equality property is Property 3 there; parse robustness is Property 6. No separate test file needed."
first_passing: 2026-04-24
---

# attestation-roundtrip

**Claim:** The `Attestation` struct is serializable and deserializable such that `deserialize(serialize(a)) == a` for every semantically-valid `a`.

**Property (pointwise):**
- For any Hegel-generated `Attestation` value, round-trip through the serializer returns a bytewise-equal `Attestation`.
- Partial deserialization (truncated input) returns `Err`, never panics.
- Deserializing random bytes (most of which are invalid) returns `Err`, never panics (parse-robustness).

**Test shape:** `#[derive(DefaultGenerator)]` on `Attestation`; `#[hegel::test]` draws attestations and round-trips; separate test draws `binary()` and asserts no panic.

**Field coverage to force:**
- `job_id: Uuid` — include zero UUID.
- `commit: String` — include empty, 7-char, 40-char, 64-char variants.
- `result: enum` — all variants.
- `timestamp: i64 or ISO8601` — include epoch 0, far-future, negative.
- `signature: [u8; 64]` — fixed-size array.

**Notes:** This card only tests round-trip equality. Hash-stability under reordering is a *separate* claim covered in `attestation-canonicalization`.
