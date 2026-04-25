---
id: capability-aware-committee
source: SPEC.md §5.2b + §7.1
class: A
status: encoded
test: tests/capability_aware_committee.rs
depends_on:
  - capability-match
  - vrf-assignment-uniformity
introduced_by: issue/34
---

# Capability-aware committee selection

The coordinator's committee for a job is a subset of the runners
whose registered `Capabilities` satisfy the job's `JobRequirements`.

## Falsifiable claim

Given:

- A registered fleet `F = {(runner_id, capabilities)}`,
- A job with requirements `req` and committee size `k`,
- A coordinator that runs `select_committee(F, req, k)`,

the returned committee `C` has these properties:

1. **Capability soundness** — every `id ∈ C` satisfies
   `capabilities::matches(F[id].capabilities, req) == true`. No
   incapable runner is ever selected.
2. **Capability completeness** — when `|{id : matches(F[id], req)}| ≥ k`,
   `|C| == k` and `C` is the top-k by VRF output among matching
   runners.
3. **Underprovisioning honesty** — when fewer than `k` runners match
   `req`, the coordinator does not silently undercut quorum: the job
   aborts with a logged explanation. This is essential — silently
   running a `k-1`-of-`k`-eligible committee would give an attacker
   leverage to manipulate quorum by getting other runners into states
   where they fail capability checks.
4. **VRF independence from filter** — for any two `req` values that
   admit the same set of matching runners, `select_committee` returns
   the same committee. The capability filter is a set operation; it
   doesn't reorder eligible runners.

## Why it's load-bearing

A coordinator that picks an incapable committee silently wastes the
job. Worse, an attacker who can manipulate which runners pass the
capability filter (by reporting false capabilities) can manipulate
the committee composition without ever attacking the VRF.

The companion concern — runners *lying* about their capabilities — is
out of scope for this card and gets its own follow-up: enrolled
runners must have their declared capabilities cross-verified against
their attestation environment hash, but the gate-soundness claim here
is just "the coordinator's filter does what it says."

## Test surface

`tests/capability_aware_committee.rs`:

1. **Soundness** — synthesize a fleet with mixed capabilities; for
   any random `req`, the returned committee is a subset of the
   matching set.
2. **Completeness** — when ≥ k runners match, exactly k are returned.
3. **Underprovisioning aborts** — when < k match, the function
   returns `None` (or its equivalent abort signal); no committee is
   silently formed.
4. **Order preservation** — the committee elements come from the
   matching set in the same VRF-output-order as if the filter weren't
   there (i.e., we don't accidentally re-sort after filtering).

## Out-of-scope

- Capability *honesty* (a runner falsely claiming `Wasm` runtime
  availability) — that's a future follow-up tied to attestation
  environment hashes.
- The full B-stat claim "matching-rate distribution under random
  requirements" — that's a statistical property of the distribution
  of fleets, not an algebraic claim about a single fleet.
