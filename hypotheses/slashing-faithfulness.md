---
id: slashing-faithfulness
class: A
section: §8.4
status: passing
test: tests/slashing_faithfulness.rs
depends_on: quorum-math ✓ + tamper-rejection ✓ (#35)
---

# Slashing faithfulness

When the quorum aggregator produces a definitive outcome (Pass or
Fail), runners whose attestation diverges from the consensus
artifact lose `current_stake × slash_fraction` weight. Runners whose
attestation matches the consensus are untouched. Runners not on the
ledger (unenrolled) are skipped.

## Statement

For any `(StakeLedger, consensus_artifact, attestations, fraction)`:

1. **Disagreement → slash.** Any committee member whose
   `attestation.artifact_hash != consensus_artifact` is in the
   returned `Vec<SlashEvent>`, with `slashed = floor(stake_before ×
   fraction_clamped)`.

2. **Agreement → no slash.** A committee member whose
   `attestation.artifact_hash == consensus_artifact` is **not** in
   the returned events; their stake is unchanged.

3. **Saturation.** `stake_after >= 0` always — slashing saturates
   at zero, never wraps.

4. **Fraction clamping.** Fractions outside `[0.0, 1.0]` are
   clamped: negative becomes 0 (no-op); >1.0 becomes 1.0 (zero out
   the disagreer's stake).

5. **Unenrolled skip.** An attestation whose `runner_id` isn't in
   the ledger produces no event, even if it disagrees.

6. **Ledger consistency.** After `slash_minority` returns, the
   ledger's `stake_of(id)` for every event matches `event.stake_after`.

## Class

**A** (pointwise universal). The ledger + slash logic is pure data
plus arithmetic; every property holds per-draw, no inner sampling.

## Falsification candidates

- Slashing the majority instead of the minority — Property 2 catches
  it (a majority member's stake decreased).
- Comparing only `runner_id` instead of `artifact_hash` — Property 1
  catches it (a runner who agrees would still show up in events).
- Wrap-on-underflow — Property 3 catches it (negative or
  giant-positive `stake_after` after a slash that should have
  saturated).
- Failing to clamp fraction — Property 4 catches it (fraction=1.5
  removing 1.5× the stake).
- Slashing an unregistered runner — Property 5 catches it (event
  emitted for a runner that was never on the ledger; would be a
  silent map-grow bug).

## Why this is the load-bearing property for §8.4

Without faithful slashing, the trust model degrades to "we measure
disagreement but never act on it". Property 2 is the
non-collateral-damage guarantee: an honest majority isn't punished
for outvoting a misbehaving runner. Property 1 is the symmetric
non-impunity guarantee.

The ledger is the only place in v0.3 where weighted committee
selection observes the cost of past dishonesty — every subsequent
job's `aggregate(votes, threshold, &ledger.as_stake_map())` uses
the post-slash weights, so a slashed runner's vote contributes less
to quorum until they're gone entirely.

## Coverage

- `disagreement_runners_slashed` — Property 1
- `agreement_runners_unslashed` — Property 2
- `slashing_saturates_at_zero` — Property 3
- `fraction_clamping_above_one_zeros_stake` — Property 4
- `fraction_clamping_below_zero_is_noop` — Property 4 (lower bound)
- `unregistered_runner_produces_no_event` — Property 5
- `ledger_state_matches_events` — Property 6
