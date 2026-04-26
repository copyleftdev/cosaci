---
id: concurrent-job-isolation
source: SPEC.md §7.4
class: A
status: passing
test: tests/concurrent_job_isolation.rs
depends_on:
  - quorum-math
  - merkle-log-append-only
introduced_by: issue/50
---

# Concurrent job isolation

When the coordinator processes N jobs concurrently, every
individual job's `consensus_artifact` and `Outcome` must be
**byte-equal** to what it would be under a sequential run from
the same starting state — the only thing concurrency may change
is the *order* of Merkle log appends, not their *content*.

## Falsifiable claims

For any set of pending jobs `J = {(job_id, committee, votes)}`
and any starting `(StakeMap, MerkleLog)`:

- **Per-job determinism** — the `Outcome` and consensus
  `artifact_hash` for each `j ∈ J` depend only on
  `(committee, votes, stake_at_anchor_time, threshold)`. They
  do not depend on the interleaving of the other jobs.
- **Log multiset equality** — the multiset of Merkle log
  entries after processing `J` is independent of the
  interleaving. (Order may differ; content does not.)
- **No mid-flight leakage** — a job that errors before anchor
  does not perturb the state observable by any other job. Its
  `consensus_artifact` (computed but unanchored) is recoverable
  from the journal without ambiguity.
- **Anchor-time stake** — when the coordinator reads the stake
  ledger to compute a job's quorum threshold, it sees a
  consistent snapshot. Between two reads of the same snapshot
  during one job's lifecycle, the answer doesn't change as
  another job's slashing event lands. (The state-machine model
  enforces serialized stake mutation; concurrent reads observe
  pre- or post-slash, never a torn intermediate.)

## Why this is class A

Each property is a pointwise statement over a sequence of
state-machine operations. Hegel's `state_machine` decoration
generates rule schedules of arbitrary length and the shrinker
isolates the minimum interleaving that breaks the model.

## Encoding

The falsifiable core is a Hegel `state_machine` test in
`tests/concurrent_job_isolation.rs`. It models a small concurrent
coordinator:

- A pool of pending jobs, each with a deterministic `committee
  ⊆ runner_ids` and a `vote_set: HashMap<runner_id, VoteResult>`
  drawn at job-creation time.
- Rules: `submit_job`, `aggregate_job` (compute outcome from
  collected votes, freezing the stake snapshot), `anchor_job`
  (append `consensus_artifact` to the Merkle log + record the
  job in the resolved set), `slash_runner` (mutate stake
  ledger).
- Oracle: a sequential reference run over the same job set in
  submission order. After the state machine reaches a quiescent
  state (every submitted job either anchored or escalated), the
  test asserts the resolved-set multiset matches the oracle's,
  and the Merkle log entries (as a multiset) match.

## Out of scope (follow-on)

- **Coordinator runtime rewrite to `tokio`.** This card
  encodes the *property*; the `tokio`-async runtime that
  exploits it is the runtime change tracked in #50's
  follow-on PR.
- **16-job demo burst** (acceptance criterion #3 of #50).
  The networked demo's pass-3 currently sends 2 sequential
  signed submissions — the burst lands with the runtime.
- **Criterion concurrent-jobs throughput bench** (acceptance
  criterion #4 of #50).
- **Distributed concurrency across coord shards.** The
  state-machine model is single-coord; multi-coord
  concurrency layers on the sharded-Raft + gossip primitive
  in `memory/project_scale_primitives.md`.
