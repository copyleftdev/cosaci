---
id: submission-auth-gate
source: SPEC.md §13
class: A
status: passing
test: tests/submission_auth_gate.rs
depends_on:
  - tenant-rate-limit
  - replay-protection
introduced_by: issue/46
---

# Submission auth gate

External job submissions (issue #32) carry tenant id, ed25519
signature, and a token-bucket rate-limit cost. Three gates apply
in order; only `Ok` flows reach the queue.

## Falsifiable claims

For any `(payload, pubkey, signature, registry, rate_limiter)`:

- **Unknown tenant rejected** — if `payload.tenant_id` is not in
  `registry`, `verify_and_admit` returns `UnknownTenant` and the
  rate limiter is **not** consumed.
- **Bad signature rejected** — if `SHA-256(pubkey) ≠
  registry[tenant_id].signing_fp`, OR the ed25519 signature
  doesn't verify against `canonical_bytes(payload)`,
  `verify_and_admit` returns `BadSignature` and the rate limiter
  is not consumed. Tampering with **any** field of the canonical
  payload (tenant_id, kind, a, b, deadline_secs, nonce) flips the
  verdict from `Ok` to `BadSignature`.
- **Rate-limited beyond bucket** — for a tenant with capacity
  `C`, the `(C+1)`-th valid submission within a single tick
  returns `RateLimited` (and the bucket stays at zero).
- **Tenant isolation** — tenant A can submit at full rate while
  tenant B's bucket is drained: verdicts for A's submissions
  never depend on B's bucket state.
- **Auth before rate-limit** — a forged signature can never
  drain the legitimate tenant's bucket. (`UnknownTenant` and
  `BadSignature` short-circuit before any token spend.)

## Why this is class A

Each property is a pointwise statement over the inputs of one
`verify_and_admit` call (or a deterministically-ordered sequence
of calls under a `SimClock`). No averaging, no probabilistic
distribution — Hegel can falsify a single counterexample and the
shrinker has the input space to drive at.

## Why the bad-signature ↔ wrong-pubkey verdict is intentionally
## merged

Returning distinct verdicts ("wrong pubkey" vs "valid pubkey but
bad signature") leaks an oracle for which tenant ids are
registered. The submission gate exposes one verdict for the
whole signature-failure surface; operators triage via the coord
log line that *does* distinguish the two cases.

## Out of scope (follow-on)

- Replay protection on `nonce`. The payload carries a `nonce`
  field but v0.3 does not enforce uniqueness via the bloom
  filter; a replay attack within the rate-limit window is
  detected only by the operator (a bursty pattern of identical
  artifact_hashes). The replay-protection card already covers
  the algebra; wiring it through submission_auth is the
  follow-on PR.
- Hierarchical / fair queuing across tenants. The current gate
  is per-tenant token-bucket; one tenant's burst can crowd the
  shared submission queue if the per-tenant capacity sums
  exceed `--queue-cap`.
- Distributed rate limiting across coordinator shards.
