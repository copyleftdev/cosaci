---
id: quorum-math
source: SPEC.md §8.1
class: A
status: passing
test: tests/quorum_math.rs
depends_on: "P2 (stake-weighted votes)"
first_passing: 2026-04-24
hegeltest_version: 0.8.0
---

# quorum-math

**Claim:** Pure function `aggregate(votes: &[Vote], threshold: Weight, stake: &StakeMap) -> Outcome` where `Outcome ∈ {PASS, FAIL, RETRY, ESCALATE}`. Each vote carries `runner_id` and `result ∈ {Pass, Fail}`. Voting weight is `stake[runner_id]`.

**Property (pointwise):**
- **Order-insensitivity:** permuting the vote slice gives the same outcome.
- **Dedup:** duplicate votes from the same `runner_id` count once (last-write-wins).
- **Monotone in support:** adding a `Pass` vote never degrades outcome from `PASS` to non-`PASS`; symmetrically for `Fail`/`FAIL`.
- **Fail-fast correctness:** once Σ `Fail`-weight ≥ threshold, outcome is `FAIL` regardless of remaining unseen votes.
- **Empty input:** `aggregate(&[], _, _) = RETRY` (never `PASS` or `FAIL`).
- **Below-threshold:** if neither side reaches threshold and all votes counted, outcome is `RETRY` or `ESCALATE` (escalation rule defined by spec; test documents it).
- **Tie at threshold:** exact-threshold behavior is specified and tested for each side.

**Test shape:** Hegel draws `Vec<(runner_id, result)>` + stake map + threshold. Assert all six properties.

**Bug-pattern watch:** off-by-one on threshold comparator, float/int mixing if stake ever becomes fractional, integer overflow on stake sum at public scale (use `u128` or saturating arithmetic).

**Notes:** This is the single most load-bearing A-class card. A defect here invalidates every trust guarantee downstream.
