---
id: admin-auth-gate
source: SPEC.md §13 (admin extension)
class: A
status: passing
test: tests/admin_auth_gate.rs
depends_on:
  - submission-auth-gate
  - mtls-enforcement
introduced_by: issue/53-followon
---

# Admin auth gate

The admin wire-protocol listener (`Envelope::AdminHello` etc.,
issue #53 follow-on) is the remote-management surface for
operators who don't have shell access on the coord host. It
sits **behind** mTLS (only clients with certs signed by the
coord's CA can reach the handshake) **and** requires an
ed25519 signature from a pubkey on the operator-managed
allowlist. mTLS is transport identity; the ed25519 key is
action identity.

## Falsifiable claims

For any `(set, pubkey, ts, signature, challenge, freshness, clock)`:

- **Honest hello admits** — when `pubkey`'s fingerprint is in
  `set` and `signature` is `sign(challenge ‖ ts.to_le_bytes())`
  under that key and `|ts - clock.now()| ≤ freshness`,
  `verify_admin_hello` returns `Ok { admin_id }` with the
  matched record's id.
- **Unknown admin rejected** — fingerprint not in the set →
  `Unauthorized`.
- **Tampered ts rejected** — signature is over `ts_signed` but
  the wire claims `ts_signed + Δ` → `Unauthorized` (the bytes
  hashed by the signer don't match what the verifier
  reconstructs).
- **Stale ts rejected** — `|ts - now| > freshness` →
  `Unauthorized` regardless of signature validity.
- **Wrong challenge rejected** — verifying with a different
  challenge string than the signer used → `Unauthorized`.
  (Catches replay across protocols that happen to share an
  admin keypair.)
- **Verdicts merge on failure** — `Unauthorized` covers
  unknown-pubkey, bad-signature, and stale-ts together.
  Distinct verdicts would leak which admin keys are
  configured on the coord; merging closes that oracle.

## Boundary

Freshness is a closed interval: `|ts - now| == freshness` is
fresh; `+1` is stale. Tested at all three boundary points
(inside, on, just outside).

## Why this is class A

Each property is a pointwise statement over one
`verify_admin_hello` call against a `Clock`-injected reading.
Hegel can falsify with a single counterexample.

## Out of scope (follow-on)

- **Mutating admin operations** (`agents enroll/revoke`,
  `tenants add/revoke`). v0.3 admin wire is read-only:
  `AdminListAgents` + `AdminGetLogRoot`. Mutating ops
  require an in-memory state lock + an enrollment-reload
  story; that's a separate PR.
- **Per-request signing.** v0.3 trusts the session for the
  lifetime of the mTLS connection after the hello. A
  per-request signature would let an operator restart the
  CLI between operations without redoing the handshake;
  not load-bearing for the read-only surface.
- **Audit-log persistence.** Each accepted hello logs
  `admin_id=N session opened` to `tracing`; v0.3 doesn't
  persist these to the journal. Production deployments
  should ship `journalctl` output to a SIEM.
