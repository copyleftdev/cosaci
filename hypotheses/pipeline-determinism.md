---
id: pipeline-determinism
source: SPEC.md §6.2
class: A
status: encoded
test: tests/pipeline_determinism.rs
depends_on:
  - real-runtime-determinism
introduced_by: issue/39
---

# Pipeline determinism

Two runners executing the same `Pipeline` against the same source state
must produce byte-equal `PipelineResult`s.

## Falsifiable claim

For any well-formed `Pipeline` `p` and any number of execution attempts
`n`, the multiset of `PipelineResult`s produced by `n` independent
calls to `cosaci_jobs::execute_pipeline(&p)` is a singleton.

In particular:

- The CBOR canonical encoding of a pipeline is stable across
  serializations: `decode(encode(p)) == p` byte-equal.
- Two committee members executing the same pipeline produce
  byte-equal `PipelineResult` values.
- When a mutation to a step's input changes the *observable output*
  of that step's executor, the change propagates into
  `final_artifact_hash`. (See "Hegel shrink" below for the lesson on
  why this is the right strength of claim.)
- Steps whose executors are not yet implemented produce
  `StepStatus::NotImplemented` with a deterministic `output_hash`
  (the canonical hash of the step itself) — so a partially-implemented
  coordinator still attests the same hash on every runner.

## Hegel shrink (initial encoding)

The initial encoding of this card claimed *"mutating any step's
contents deterministically changes the pipeline's `final_artifact_hash`."*
Hegel's shrinker produced a counterexample within seconds:

- Module: canned mul (`add`-export semantics: `a * b`).
- Args: `(a=0, b=0)`.
- Mutated args: `(a=1, b=0)`.

`0 * 0 = 0` and `1 * 0 = 0` — same i32 result. The `output_hash`
binds to `(module_hash, result)`, so identical results produce
identical hashes regardless of how the inputs differ. The mutation
genuinely doesn't propagate.

This was a successful falsification — the spec was claiming more
than the system guarantees. The corrected claim above bounds the
mutation property to "the executor isn't lossy on the input change."
The universal form is intentionally not claimed, because two
different inputs producing the same output is the desirable
content-addressing property: a CI build with logically-equivalent
source attests the same artifact regardless of cosmetic differences.

## Why it's load-bearing

This claim is a *prerequisite* for the entire trust chain. If two
runners can disagree on the bytes of a `PipelineResult` for the same
`Pipeline`, then:

1. Their attestations carry different `artifact_hash` values.
2. The quorum aggregator records disagreement.
3. The reputation tracker can't tell whether the disagreement reflects
   honest non-determinism (a flaky test) or dishonest misexecution.

The system's whole proposition — "a quorum of independent runners
agreeing on what they observed" — collapses if `execute_pipeline` is
non-deterministic. Every downstream property test (slashing,
capability matching, federation) implicitly depends on this one.

## Test surface

`tests/pipeline_determinism.rs`:

1. **CBOR round-trip** — `decode(encode(p)) == p` for any synthesized
   pipeline.
2. **Repeated-execution stability** — `execute(p)` called N times in a
   row produces the same `PipelineResult` bytes.
3. **Step-mutation propagation** — mutating any byte of any step
   produces a different `final_artifact_hash`.
4. **NotImplemented determinism** — pipelines containing
   not-yet-implemented step types still produce stable hashes; the
   only valid `output_hash` for a `NotImplemented` step is the
   canonical hash of the step value itself.

## Out-of-scope

- Cross-runner determinism for steps that touch the network (#40
  source fetch, #54 egress) — those rely on external state and have
  their own cards.
- `ExecNative` determinism — that's a system-runtime claim, gated by
  the Linux harness; sits with #43 (resource limits) when the
  executor lands.

## Evolution

When step executors land, this card stays the umbrella claim and each
new step type gets its own sub-claim if it introduces a new source of
non-determinism (network, clock, randomness). The pure-DSL part of
this card never changes.
