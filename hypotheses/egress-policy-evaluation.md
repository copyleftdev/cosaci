---
id: egress-policy-evaluation
class: A
section: §6.4
status: passing
test: tests/egress_policy_evaluation.rs
depends_on: cosaci-jobs (#54)
---

# Egress policy evaluation

The pure half of issue #54: given a `NetworkPolicy` and a single
outbound `EgressAttempt`, what's the `Decision`? The class C half
(Linux netns interception that actually enforces the decision)
lands separately, gated on `HEGEL_LINUX_HARNESS=1`.

This card is the load-bearing falsifiable claim because the
decision logic is what every operator actually configures. If a
runner enforces a policy that disagrees with the documented
evaluation, two committee members executing the same step on the
same `(pipeline, source)` produce different `network_violations`
fields and the quorum aggregator sees disagreement on what should
be a deterministic field. Slashing follows.

## Statement

For any `(NetworkPolicy, EgressAttempt)`:

1. **Empty allowlist + Deny default ⇒ Deny.** No allowlist entry
   matches; default fires.

2. **Empty allowlist + Audit default ⇒ Audit.** Same path,
   different default.

3. **Matching `Host` entry ⇒ Allow.** A `Host { hostname, port,
   scheme }` entry matches when the attempt has the same hostname
   AND (port is 0 OR port matches) AND scheme matches (`Tcp`
   matches anything, otherwise exact).

4. **Matching `Cidr` entry ⇒ Allow.** A `Cidr { cidr, port_range }`
   entry matches when `addr` is inside the CIDR AND the port falls
   in the range (or both endpoints are 0, meaning any port).

5. **Direct-IP attempts skip Host entries.** An `EgressAttempt`
   with `hostname: None` never matches a `Host` entry, even if the
   resolved IP would.

6. **Invalid CIDR strings match nothing.** A `Cidr { cidr:
   "not-a-cidr" }` entry never matches; operator typos can't widen
   the policy.

7. **CIDR /0 matches everything (within family).** `0.0.0.0/0`
   matches every IPv4 attempt; `::/0` matches every IPv6 attempt.
   `0.0.0.0/0` does NOT match v6, and vice versa — operators
   wanting both add both entries (see `allow_all` helper).

8. **First match wins; iteration order doesn't change Allow.**
   If any entry in `policy.allow` matches, the result is `Allow`
   regardless of where in the list it sits.

## Class

**A** — pure data + arithmetic + IP comparisons. No I/O, no
external state.

## Falsification candidates

- Returning `Allow` from an empty allowlist when default is `Deny`
  (the catastrophic open-by-default bug) — Property 1 catches it.
- Treating `port: 0` as "exact match port 0" instead of "any port"
  — Property 3 catches it.
- IPv4 mask off-by-one (e.g. using `(32 - prefix)` shift on a
  prefix of 0, which is UB on a 32-bit shift) — Property 7's
  `0.0.0.0/0` test exercises the prefix=0 path.
- Falling through CIDR parse errors as Allow — Property 6 catches
  it.

## Coverage

- `empty_allowlist_with_deny_default_yields_deny` — Property 1
- `empty_allowlist_with_audit_default_yields_audit` — Property 2
- `matching_host_entry_yields_allow` — Property 3
- `matching_cidr_entry_yields_allow` — Property 4
- `direct_ip_attempt_skips_host_entry` — Property 5
- `invalid_cidr_does_not_match` — Property 6
- `slash_zero_matches_within_family_only` — Property 7
- `first_match_wins_regardless_of_position` — Property 8
- `smoke_realistic_cargo_fetch_policy` (deterministic) — sanity check

## Out of scope (follow-on)

- **Linux netns interception (class C, gated).** Spawning the
  step inside a network namespace and routing outbound TCP
  through an in-process proxy that calls `evaluate(...)` per
  connection. Lands in a separate PR with `HEGEL_LINUX_HARNESS=1`
  guarding the test.
- **`StepOutput::network_violations`.** The data field that
  records non-allowlisted attempts (under `Audit` default).
  Adding this field to `StepOutput` requires a wire shape change
  + canonical-encoding update; defer until the netns
  enforcement lands so the field has something to populate.
