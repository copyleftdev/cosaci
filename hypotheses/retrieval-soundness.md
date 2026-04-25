---
id: retrieval-soundness
class: A
section: §10.4
status: passing
test: tests/retrieval_soundness.rs
depends_on: merkle-log-append-only ✓ + merkle-log-persistence ✓
---

# Retrieval soundness

A retrieved `JobBundle` from the coordinator's read API is verifiable
against its own `log_root`. Tampering with any byte of the bundle
(attestation, proof, root, or artifact) causes verification to fail.

## Statement

For any sequence of `(record, append)` operations on a paired
`(records: HashMap<u64, JobRecord>, log: MerkleLog)`:

1. **Proof verifies.** For every `job_id` that has been recorded,
   `build_bundle(records, log, job_id)` returns `Some(bundle)` and
   `verify_inclusion(bundle.merkle_proof, bundle.log_root) == true`.

2. **Tamper-evidence.** Mutating any byte of `bundle.merkle_proof.entry`
   or `bundle.log_root` causes `verify_inclusion` to return `false`.

3. **Stable bundle.** Calling `build_bundle` twice with the same
   `(records, log, job_id)` produces byte-identical bundles (CBOR
   round-trip equal).

4. **Unknown job → None.** For any `job_id` not in `records`,
   `build_bundle` returns `None`.

## Class

**A** (pointwise universal). Each property holds per-draw, no inner
sampling needed.

## Falsification candidates

- Building the bundle from current root instead of `root_at(length)` —
  proof becomes invalid as soon as the next entry lands.
- Storing `log_position` without `log_length_at_anchor` — every
  retrieval would have to choose either "current root" (unstable) or
  "some other length" (incorrect). Property 3 catches this.
- Using a different inclusion-proof algorithm in build vs. verify —
  Property 1 catches this immediately.
- Forgetting the entry-bytes binding in the proof — Property 2 (tamper)
  catches a verifier that ignores `proof.entry`.

## Why this is the load-bearing property for §10.4

The whole point of the read API is that an external auditor with no
trust in the coordinator can independently verify a job ran honestly.
If retrieval is unsound — if the coordinator can hand out bundles that
verify but lie about content, or that don't verify at all — the audit
trail is decorative.

Properties 1 + 2 are the floor: the produced bundle either verifies as
written or is detectably tampered. Property 3 catches a class of
"latest-state" bugs that only show up under concurrent appends.
Property 4 is hygiene: an empty registry shouldn't fabricate bundles.

## Coverage

- `proof_verifies_for_every_recorded_job` — Property 1
- `tamper_in_root_is_rejected` — Property 2 (root)
- `tamper_in_entry_is_rejected` — Property 2 (entry)
- `bundle_is_stable_across_calls` — Property 3
- `unknown_job_returns_none` — Property 4
