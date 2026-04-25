---
id: enrollment-gate-enforcement
class: A
section: §5.1
status: passing
test: tests/enrollment_gate_enforcement.rs
depends_on: sha2 + signing pubkey shape (#45)
---

# Enrollment-gate enforcement

The coordinator's pre-provisioned `EnrolledRunners` set is the final
say on whether a registering agent is allowed into the trust set. An
agent whose `(runner_id, signing_fp, vrf_fp)` triple isn't in the
set must be rejected, **regardless** of valid mTLS or valid VRF
proof of possession.

## Statement

For any `EnrollmentSet` populated by `insert(record)` calls and any
`(runner_id, signing_fp, vrf_fp)` triple submitted at registration:

1. **Enrolled passes.** A triple that exactly matches an inserted
   record (same `runner_id` AND same fingerprints) returns
   `is_enrolled == true`.

2. **Unenrolled rejected.** A triple whose `runner_id` is not in the
   set returns `is_enrolled == false`.

3. **Impersonation rejected.** A triple whose `runner_id` is in the
   set but whose `signing_fp` OR `vrf_fp` differs from the enrolled
   value returns `is_enrolled == false` — flipping a single byte of
   either fingerprint is enough.

4. **Empty set rejects everyone.** An empty `EnrollmentSet` returns
   `is_enrolled == false` for any input.

5. **File-format round-trip.** A record written out via the v0.3
   text format (whitespace-separated:
   `runner_id signing_fp_hex vrf_fp_hex enrolled_at_unix_ns initial_reputation`)
   parses back to a record with byte-identical fingerprints,
   matching `runner_id`, and matching `enrolled_at_unix_ns`.

## Class

**A** (pointwise universal). The set is pure data; every property
holds per-draw.

## Falsification candidates

- Looking up by `runner_id` only and ignoring fingerprints — Property 3
  catches it: an attacker with a CA-signed cert claiming an enrolled
  `runner_id` is admitted.
- Comparing fingerprints with `<` instead of `==` (e.g. via incorrect
  prefix match) — Property 1 catches the false reject and Property 3
  catches the false accept.
- Treating an empty file as "no enforcement" instead of "no one
  enrolled" — Property 4 catches it. The "no enforcement" mode is
  an explicit empty-`--enrollment` flag, NOT an empty file.
- Hex-parser off-by-one in `parse_hex32` — Property 5 catches it.

## Why this is the load-bearing property for §5.1

Without the gate, registration is open to any holder of a
CA-signed mTLS cert plus a self-issued VRF keypair. The mTLS PKI
governs *who can talk*; the enrollment set governs *who counts*.
A compromised runner whose private key was leaked stays in the
committee pool forever without this gate (the only out is rotating
the CA, which expels everyone).

Property 3 is the one that distinguishes "real auth" from "good
enough" — a system that gates by `runner_id` alone is broken in a
specific subtle way (anyone who learns an enrolled id can claim
that slot with their own keys) that the property exercises directly.

## Coverage

- `enrolled_triple_passes` — Property 1
- `unenrolled_runner_id_rejected` — Property 2
- `wrong_signing_fp_rejected` — Property 3 (signing fp)
- `wrong_vrf_fp_rejected` — Property 3 (vrf fp)
- `empty_set_rejects_everyone` — Property 4
- `record_round_trips_through_file_format` — Property 5
