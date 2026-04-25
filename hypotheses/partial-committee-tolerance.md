---
id: partial-committee-tolerance
class: A
section: §8.5
status: passing
test: tests/partial_committee_tolerance.rs
depends_on: quorum-math ✓ (#61)
---

# Partial-committee tolerance

A committee member that fails to respond within the per-runner
deadline does not abort the job. The responding subset still
aggregates to a deterministic outcome, and the missing runners are
recorded for downstream reputation tracking.

This replaces the historical `?`-bail-on-any-IO-error behavior
that turned every dropped TCP connection into a job failure — a
daily occurrence in any fleet of laptops that wake/sleep/reconnect.

## Statement

For any `(committee, votes_subset, stake_map, threshold_fn)`:

1. **Responding/missing partition.** `resolve_with_dropouts`
   returns `responding ∪ missing == committee` (set-equal, with
   no duplicates), and `responding ∩ missing == ∅`. The order
   within each list matches input order in `committee`.

2. **Outcome equals subset aggregate.** The returned `outcome`
   equals `aggregate(votes_subset, threshold_fn(responding_stake),
   stake_map)`. Two callers with the same `(committee, votes,
   stake_map, threshold_fn)` produce byte-identical
   `PartialOutcome` values.

3. **Single-failure tolerance.** For `committee.len() ≥ 3` and a
   responding subset of size `committee.len() - 1`, the outcome is
   well-defined (Pass / Fail / Escalate) and deterministic — never
   panics, never returns `Err`.

4. **Threshold scales with responding stake.** The threshold
   applied is `threshold_fn(responding_stake)`, NOT
   `threshold_fn(full_committee_stake)`. A 2/3-weighted majority
   of who actually responded is the right threshold; using the full
   committee's stake would make every partial response automatically
   fail to meet the bar even when the responders unanimously agree.

5. **Empty response.** With no votes (every committee member
   missing), `outcome` is whatever `aggregate(&[], 0, _)` produces
   (currently `Outcome::Fail`); `responding` is empty;
   `missing == committee`.

## Class

**A** (pointwise universal). The resolver is pure data + arithmetic;
every property holds per-draw.

## Falsification candidates

- Computing the threshold against full-committee stake instead of
  responding-subset stake — Property 4 catches it (a unanimous
  partial committee fails to reach quorum).
- Dropping a runner from `missing` when they sent a malformed
  envelope — Property 1 catches it (set-completeness violation).
- Bailing the whole job on any I/O error — there's no pure-function
  analog of this (it's a coord-side change), but the integration
  invariant is "the job still produces an outcome line in the log
  even when one runner times out."

## Coverage

- `responding_and_missing_partition_committee` — Property 1
- `outcome_equals_subset_aggregate` — Property 2
- `single_failure_in_committee_of_three_yields_outcome` — Property 3
- `threshold_uses_responding_stake_not_committee_stake` — Property 4
- `empty_response_does_not_panic` — Property 5
- `smoke_three_runners_one_drops` (deterministic) — sanity check

## Out of scope

- Reputation impact of the `MissingAttestation` signal: the
  `MissingAttestation` reputation decrement (`δ_miss = δ_disagree
  / 4` per the issue) lands when the slashing/reputation ledger
  separation lands (issue #35 follow-on / #61 phase 2).
- The coord-side network timeout itself isn't a Hegel property —
  it's exercised by the existing `demo_networked` smoke test (and
  the new `--runner-timeout-secs` flag is unit-tested by the
  smoke run not regressing).
