---
id: tamper-rejection
source: SPEC.md §9.1
class: A
status: passing
test: tests/tamper_rejection.rs
depends_on: "ed25519-dalek 2.2.0"
first_passing: 2026-04-24
---

# tamper-rejection

**Claim:** Ed25519 signatures protect attestation integrity. A valid signature over a message verifies; any tampering with message or signature rejects; a signature under one keypair does not verify under another.

**Property (pointwise):**
- **Round-trip correctness:** `verify(pk, msg, sign(sk, msg)) = Ok` for any `(sk, pk)` from keygen.
- **Message mutation rejects:** for any `msg ≠ msg'`, `verify(pk, msg', sign(sk, msg)) = Err`.
- **Signature mutation rejects:** for any `sig ≠ sig'` (≥ 1 bit flipped), `verify(pk, msg, sig') = Err`.
- **Cross-key rejection:** for `pk' ≠ pk` from a different keypair, `verify(pk', msg, sign(sk, msg)) = Err`.

**Test shape:** direct `#[hegel::test]`. Hegel draws bytes for msg and mutation points; ed25519-dalek is the system under test (wrapped, not reimplemented).

**Scope:** We test our wrapper's correct usage of ed25519-dalek, not the correctness of Ed25519 itself. If the wrapper miscomputes the signing input (e.g., fails to hash deterministically, or includes a nonce), this card catches it.

**Notes:** Batch verification, if adopted at scale, warrants its own card (batch verify must reject any batch containing a bad sig).
