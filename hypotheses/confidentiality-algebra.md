---
id: confidentiality-algebra
source: SPEC.md §9 (new, required at public scale)
class: A
status: passing
test: tests/confidentiality_algebra.rs
depends_on: "chacha20poly1305 0.10 (ChaCha20-Poly1305 AEAD)"
primitive_pick: "ChaCha20-Poly1305 AEAD (256-bit key, 96-bit nonce); same primitive for DEK encryption and KEK-wrapped DEK"
first_passing: 2026-04-24
note: "Does NOT defend against a malicious *assigned* runner (they legitimately hold the DEK). Confidentiality-from-runners requires TEE — see tee-attestation (class C)."
---

# confidentiality-algebra

**Claim:** Job payloads are encrypted with a per-job data-encryption key (DEK). The DEK is wrapped for each assigned runner using the runner's key-encryption key (KEK). Only assigned runners can decrypt the payload. Key rotation preserves old-ciphertext readability under the old key only.

**Property (pointwise):**
- **Round-trip:** `decrypt(encrypt(msg, dek), dek) == msg`.
- **Wrong-key rejection:** `decrypt(ct, dek') = Err` for `dek' ≠ dek` (authenticated encryption; no silent wrong-plaintext).
- **Wrap/unwrap correctness:** `unwrap(wrap(dek, kek), kek) == dek`; `unwrap(wrap(dek, kek), kek') = Err`.
- **Assignment-gated decryption:** a runner not in the assignment set has no `wrap(dek)` addressed to its KEK, so cannot decrypt even with access to the ciphertext.
- **Rotation:** after rotating KEK from `k_old` to `k_new`, ciphertexts wrapped under `k_old` still unwrap under `k_old`, not under `k_new`.

**Test shape:** direct `#[hegel::test]`. Hegel draws message bytes, generates keypairs for two runners, tests all four axioms.

**Scope:** At-rest encryption of the attestation log is a separate primitive (bulletin-level). Transport encryption is `mtls-enforcement` (class C). This card is the envelope-over-job-payload claim only.

**Notes:** Does not defend against a malicious assigned runner (they legitimately see the payload). Confidentiality-from-runners would require TEE — see `tee-attestation` (class C).
