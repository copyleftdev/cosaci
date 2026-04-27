---
id: capture-log-determinism
source: SPEC.md §10.1 / SPEC.md §6.2
class: A
status: passing
test: tests/capture_log.rs + crates/cosaci-protocol/tests/attestation_bundle_wire.rs
depends_on:
  - exec-native-determinism
  - pipeline-determinism
introduced_by: issue/108 PR 1 of N
---

# CaptureLog determinism

`Step::CaptureLog { name }` reads the most recent
`Step::ExecNative`'s captured stdout + stderr (already
bounded at `MAX_CAPTURE_BYTES` = 16 MiB by the executor)
and emits two `CapturedOutput` records into the per-run
`PipelineResult::captures` accumulator: `<name>.stdout`
and `<name>.stderr`. With no preceding ExecNative, the
step is `Failed` deterministically — there are no bytes
to capture.

This PR (108 PR 1 of N) lands the **executor** for
CaptureLog. The wire-format extension (an
`AttestationBundle` envelope that carries the captures
alongside the signed `Attestation`) is a follow-on PR.

## What changed

- `PipelineResult` gained `captures: Vec<CapturedOutput>`.
  The field is `#[serde(default, skip_serializing_if =
  "Vec::is_empty")]`, so existing producers that emit no
  captures yield byte-identical wire output to pre-#108.
  The canonical attestation hash, `final_artifact_hash`,
  binds only `steps` — capture payload size doesn't shift
  the hash and capture/no-capture pipelines remain
  committee-comparable.
- `execute_native_step` now returns
  `(StepOutput, NativeCaptures)`. The captures live in a
  per-pipeline-run slot threaded through the step loop;
  any subsequent CaptureLog reads from that slot.
- `Step::CaptureLog` rotated off the `NotImplemented`
  surface; the `not_implemented_steps_are_deterministic`
  property test now uses `Step::CaptureArtifact` (still
  pending).

## Falsifiable claims

For any `(ExecNative, CaptureLog)` pair:

- **Round-trip** — the `CaptureLog`'s emitted records have
  `bytes_inline` byte-equal to the ExecNative's observed
  stdout/stderr, `length` equal to the byte count, and
  `sha256` equal to `Sha256::digest(bytes_inline)`.
- **Naming** — captures are named `<name>.stdout` and
  `<name>.stderr` from the operator's `Step::CaptureLog`
  argument; `step_index` points at the CaptureLog step
  itself, not the source ExecNative.
- **Most-recent-wins** — when two `ExecNative` steps
  precede a `CaptureLog`, the captures are from the
  *second* ExecNative. Re-binding on each ExecNative is
  intentional: a pipeline that wants to keep multiple
  outputs uses one CaptureLog per ExecNative.
- **Orphan is Failed** — a `CaptureLog` with no preceding
  ExecNative returns `StepStatus::Failed` with a
  deterministic `output_hash` bound to
  `(step, "no_preceding_exec_native")`.
- **Empty by default** — a pipeline without any
  `Step::CaptureLog` produces `captures.is_empty() == true`.
- **Determinism** — same pipeline, same external state,
  byte-equal `PipelineResult` (captures included) across
  runs.
- **Hash stability** — `final_artifact_hash` is the same
  whether `captures` is empty or non-empty for the same
  `Pipeline`. (Captures aren't part of the hash chain;
  the canonical attestation hash binds only `steps`.)

## Wire extension (#108 PR 2 of N)

The `Envelope::SubmitAttestation` payload moved from a bare
`Attestation` to an `AttestationBundle`:

```rust
pub struct AttestationBundle {
    pub attestation: Attestation,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub captures: Vec<CapturedOutput>,
}
```

The agent populates `captures` from
`PipelineResult::captures` (the slot threaded through the
step loop in PR 1). The coord destructures and logs each
capture's name + kind + length + sha256 prefix; persistence
+ retrieval API land in PR 3.

**The signature on `attestation` covers only the canonical
attestation bytes**, not the captures. That's intentional —
captures are agent-provided evidence whose integrity is
bound by each record's own `sha256`. A verifier checks
(1) the attestation signature, then (2) for each capture,
`Sha256::digest(bytes_inline) == sha256`.

### Wire-level falsifiable claims

- **Round-trip stability** — encode → decode → encode is
  byte-equal on the second-encode, for both empty-captures
  and populated bundles.
- **`captures` skip-if-empty** — a captureless bundle
  serializes shorter than a populated one with the same
  `Attestation`. (The CBOR map omits the `captures` key
  entirely when empty.)
- **Capture integrity over the wire** —
  `Sha256::digest(decoded.bytes_inline) == decoded.sha256`
  after round-trip. Tampering with `bytes_inline` between
  encode and decode is detectable by re-hashing.

Falsifications: `crates/cosaci-protocol/tests/attestation_bundle_wire.rs` (4 tests, all pointwise).

## Out of scope (follow-on)
- **Per-step `max_log_bytes` operator override**: today
  the cap is the hard-coded `MAX_CAPTURE_BYTES` (16 MiB).
  An operator-tunable knob on `Limits` lands later.
- **CaptureArtifact**: reads a file from the previous
  step's workdir. Blocked on a real workdir-routing story
  (the SourceFetch → ExecNative workdir hand-off, currently
  not threaded through). Lands in a subsequent #108 PR.
- **Truncation determinism**: a stdout > 16 MiB is
  silently capped today. The `length` field reflects the
  pre-truncation total, but the `sha256` is over the
  truncated prefix. Documented but not yet a falsifiable
  property test (would need a fixture binary that emits
  > 16 MiB deterministically — heavier than this PR).
