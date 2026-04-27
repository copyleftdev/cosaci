# CosaCI Security Policy

This document is project-specific. The general
[copyleftdev/.github SECURITY.md](https://github.com/copyleftdev/.github/blob/main/SECURITY.md)
covers reporting mechanics; this one covers what counts as a
vulnerability **for a system whose product is itself security
attestation**.

## Reporting

Use GitHub's **private vulnerability reporting** on this repo's
**Security** tab. Do not file public issues for security
vulnerabilities.

Acknowledgment within 72 hours. Coordinated disclosure on a
case-by-case timeline; ninety-day default.

## In-scope vulnerability classes

CosaCI's whole point is making CI dishonesty detectable. A
vulnerability is anything that breaks one of these guarantees in
the audit trail (`hypotheses/index.md` is the SSOT).

### Critical

- **Trust-chain breaks.** Anything that lets an attacker get a
  forged attestation past the coordinator's quorum without being
  detected — committee-bypass, signature forgery,
  hash-collision-by-construction, replay-window bypass beyond the
  documented `bloom-fp-rate` envelope.
- **Sandbox escapes.** A WASM module that escapes wasmtime's
  isolation or exceeds its declared `Limits` without producing
  `LimitExceeded`. Equivalent for `Step::ExecNative`: a native
  child that exceeds `Limits.memory_mb` without the cgroup-v2
  OOM killer firing + `memory.events.local` recording it, or
  exceeds `cpu_seconds` without the polled `cpu.stat::usage_usec`
  watchdog killing it.
- **Capture-integrity bypass.** A capture in an
  `AttestationBundle` whose `sha256` field disagrees with
  `bytes_inline` after wire round-trip, OR an on-disk persisted
  capture whose stored bytes disagree with the recorded hash.
  Captures are agent-provided evidence whose integrity is bound
  by per-record SHA-256, not by the attestation's signature —
  any path that lets a man-in-the-middle modify capture bytes
  without the auditor detecting it via re-hashing is in scope.
- **mTLS bypass.** Any path where a client without a valid
  CA-signed cert can register, vote, or read attestations.
- **Enrollment-gate bypass** (#45). A runner with a valid mTLS
  cert + valid VRF proof but **not in the enrollment file** that
  passes `accept_fleet`.
- **Slashing evasion.** A path where a runner whose attestation
  diverges from the consensus artifact can avoid being slashed.
- **Read-API tampering** (#44). A returned `JobBundle` whose
  `merkle_proof` verifies but whose `consensus_artifact` doesn't
  match what was actually anchored.

### High

- **Determinism breaks.** A pipeline that two runners executing
  honestly compute different `output_hash` values for. (This is
  what `pipeline-determinism` and `real-runtime-determinism`
  guard.)
- **Resource-limit cap-bypass** (#43, #107). A WASM module or
  native `ExecNative` step that exceeds its `cpu_seconds`,
  `memory_mb`, or `wall_seconds` budget without trapping or
  being recorded as `LimitExceeded`. **Note:** the v0.5 sandbox
  intentionally does NOT enforce filesystem isolation or egress
  policy on `ExecNative` — that's v0.6's mount-namespace + netns
  work (issue #107 PR 4-5). A native step in v0.5 CAN read the
  parent's filesystem; pre-v0.6 deployments should treat all
  tenants as cooperative. Documented in
  `hypotheses/exec-native-determinism.md` under "What this PR
  does not enforce." Reports of "ExecNative reads ~/.ssh" against
  v0.5 are documented limitation, not vulnerability; against v0.6+
  they're in scope.
- **Persistent-log corruption-on-restart** (#33). Any path where
  `MerkleLog::<FileStore>::open(path)` accepts a corrupted file
  silently rather than rejecting it with `InvalidData`.

### Medium / informational

- **Audit-trail regressions** — a hypothesis card that was
  passing in `hypotheses/index.md` becomes falsifiable in a way
  that wasn't documented as a follow-on.
- **CRL hot-reload races** (#8) — a cert revocation that doesn't
  propagate within a job round.
- **Capability-aware committee underprovisioning silence** —
  selection that doesn't return `None` when fewer than `k`
  runners match the requirements (the catastrophic case is
  silent quorum reduction, which property
  `capability-aware-committee` explicitly tests).

## Out of scope

- **Hosted CI vendor incidents.** CosaCI is the alternative to
  hosted CI — we have no comment on hosted-CI breaches.
- **Operator-misconfiguration.** Running coord with an empty
  enrollment file (`--enrollment` unset → gate disabled) is
  documented behavior, not a vulnerability.
- **Plaintext stake / reputation.** Stake is a public concept by
  design; the trust model is "everyone sees the weighted vote",
  not "the votes are private". Don't report "stake is leaking".
- **Demo binaries.** `cosaci-demo`, the `Dockerfile.bootstrap`
  cert generator, and `bins/cosaci-demo/src/bin/verify.rs`
  are intentional demo plumbing. The bootstrap script generates
  certs into a Docker volume by design — that's the demo
  workflow, not a leak.

## Cryptographic primitives

CosaCI's primitives are documented in
`memory/project_scale_primitives.md` and frozen for v0.x:

- **Signing:** ed25519-dalek 2.x (Ed25519). Used for attestation
  signatures and TLS handshakes.
- **VRF:** schnorrkel 0.11 (sr25519) + merlin 3.0 transcripts.
  Used for committee selection and registration proof-of-possession.
- **Hashing:** SHA-256 (sha2 crate). Used for module hashes,
  attestation hashes, fingerprints, Merkle leaves, output hashes.
- **Symmetric:** chacha20poly1305 0.10. Used for the
  `confidentiality-algebra` primitive (encrypted job payloads).
- **TLS:** rustls 0.23 with the ring backend. Used for all
  inter-component communication.

A vulnerability in any of these crates that affects the
algorithms we use is in scope. We track the crypto stack
explicitly in `dependabot.yml`'s `crypto` group so updates land
in a single PR with the full transitive picture visible.

## Coordinated disclosure expectations

- **Acknowledgment within 72 hours.**
- **Initial assessment within 7 days.**
- **Fix timeline negotiated.** Critical vulns block the next
  release; high vulns make the next minor; medium vulns are
  scheduled alongside regular work.
- **Credit.** We name reporters in release notes and any CVE we
  file (or anonymously, your choice). The audit-trail card
  affected by the fix gets a "Falsified by CVE-…" footnote so
  the historical record is honest.
- **Public disclosure** happens at fix-release time unless a
  longer timeline is negotiated. The Hegel property test that
  would have caught the vuln (had it existed) is filed as a
  separate issue alongside the fix.

## What to include in a report

- Affected version, commit, or tag.
- Reproduction — minimum viable, ideally with a Hegel property
  shape we can encode against the existing audit trail.
- Impact assessment: which trust-chain claim from
  `hypotheses/index.md` does this falsify?
- Your preferred disclosure timeline.
