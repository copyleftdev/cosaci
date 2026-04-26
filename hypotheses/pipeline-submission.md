---
id: pipeline-submission
source: SPEC.md §13 (v0.5 lift) / SPEC.md §6.2
class: A
status: passing
test: tests/submission_auth_gate.rs + bins/cosaci-coordinator/src/main.rs (tests mod)
depends_on:
  - submission-auth-gate
  - pipeline-determinism
introduced_by: issue/106
---

# Pipeline-shaped submission

The v0.3 submission gate accepts `JobSubmissionPayload`, a canned
`(kind, a, b)` triple. v0.5 (#106) lifts the wire submission to
carry a full `cosaci_jobs::Pipeline` (multi-step: `SourceFetch +
ExecWasm + ExecNative + CaptureLog + CaptureArtifact`).

This card covers the **wire + auth-gate** half of #106. The
coord-side `Pipeline` decode and execution are tracked under
`pipeline-determinism` (already passing, #39) and the v0.5
execution issues (#107, #108).

## Shape

```rust
pub struct PipelineSubmissionPayload {
    pub tenant_id: TenantId,
    pub pipeline_cbor: Vec<u8>,   // opaque CBOR — see below
    pub deadline_secs: u32,
    pub nonce: u128,
}
```

The pipeline is carried as **opaque CBOR bytes**, not the typed
`Pipeline`. Two reasons:

1. **Layer separation.** The auth gate (`cosaci-state`) doesn't
   need to know about pipeline structure; the signature commits
   to the exact bytes the producer emitted, and the coord
   deserializes into `Pipeline` after the gate returns `Ok`.
   This keeps `cosaci-state` free of a `cosaci-jobs` dep
   (which would transitively pull in `cosaci-wasm` →
   `wasmtime` — a heavy footprint for an auth layer).
2. **Round-trip stability.** Ciborium produces canonical CBOR
   from a serde-derived struct; the producer's bytes are the
   verifier's bytes. The signing client builds the `Pipeline`,
   ciborium-encodes once, signs, and sends the same bytes the
   verifier decodes.

## Falsifiable claims

For any `(payload, pubkey, signature, registry, rate_limiter,
replay_guard)`:

- **Well-formed pipeline payload admitted** — a payload signed
  by the registered keypair on a fresh nonce, within the rate
  bucket, returns `Ok` from `verify_and_admit_pipeline`,
  regardless of the contents of `pipeline_cbor` (the gate is
  agnostic to pipeline shape).
- **Cross-shape unforgeability** — a signature over the legacy
  `JobSubmissionPayload` does **not** authorize a
  `PipelineSubmissionPayload` with the same `tenant_id` and
  `nonce`. The two payload types canonicalize to different CBOR
  byte sequences (different field tags), so a signature over
  one fails verification against the other. This is the
  load-bearing claim that the v0.5 lift can run alongside the
  legacy v0.3 wire without an attacker substituting a small
  legacy signature for a pipeline submission.
- **Canonical bytes round-trip stable** — re-encoding the same
  `PipelineSubmissionPayload` yields byte-identical output.
  Ciborium-on-serde is deterministic for this shape; the
  producer-signs / verifier-recomputes split depends on it.

The four-stage gate (tenant-lookup → signature → replay →
rate-limit) and its short-circuit ordering inherit from
`submission-auth-gate` — the pipeline variant reuses the same
`RateLimiter` and `ReplayGuard`, so an attacker can't spend a
tenant's bucket via either shape, and a nonce admitted on one
shape is rejected as `ReplayDetected` on the other.

## Why this is class A

Each property is a pointwise statement over the inputs of one
`verify_and_admit_pipeline` call (or an in-test pair of legacy
+ pipeline calls). No averaging, no probabilistic distribution
— Hegel can falsify a single counterexample.

## Coord-side dispatch (#106 PR 2 of N)

The coord stdin reader accepts both wire shapes via a hand-
rolled dispatcher, **not** `#[serde(untagged)]`:

```text
{"kind":"add",...}              → JobSubmission::Legacy
{"pipeline_cbor_hex":"...",...} → JobSubmission::Pipeline
```

Why hand-rolled, not untagged: serde untagged-enum dispatch
buffers the JSON into a `serde_json::Value` to try each
variant. `Value`'s number type round-trips through f64, so
**any line carrying a u128 `nonce` silently fails dispatch**.
`parse_submission_line` peeks the discriminator on a `Value`
and then re-deserializes the **raw** line directly into the
chosen struct, which bypasses the f64 path and preserves
u128. Regression tests live in `tests::*_with_u128_nonce_parses`.

### Coord-side falsifiable claims

For every NDJSON line the coord reads:

- **Shape dispatch is deterministic and exhaustive** —
  presence of `pipeline_cbor_hex` ⇒ pipeline shape; otherwise
  legacy shape; lines satisfying neither schema are dropped at
  the parser. No line is silently mis-classified.
- **Pipeline shape passes through `verify_and_admit_pipeline`** —
  the coord `check_submission` dispatches by variant; pipeline
  submissions never get gated through the legacy
  `verify_and_admit` (and vice versa).
## End-to-end execution (#106 PR 3 of N)

The coord reader now resolves both wire shapes into a unified
`RunSubmission { pipeline, deadline_secs, origin }` that the
run loop dequeues and hands directly to `run_one_job`. Legacy
lines build a single-step ExecWasm pipeline at the reader;
pipeline lines `ciborium`-decode `pipeline_cbor_hex` into a
`cosaci_jobs::Pipeline`. CBOR-decode failures are dropped with
a warn and do not enter the queue.

`run_one_job`'s `log_module: &[u8]` parameter (a v0.3 vestige
that was only used to print a hash prefix in the per-job log
line) is dropped; the log line now reports
`pipeline_hash=…`, derived from
`cosaci_jobs::canonical_encoding(&pipeline)`. This is a
no-op functionally — the agent-side `Envelope::Assign` already
carried the full Pipeline (line 843 of `bins/cosaci-coordinator/
src/main.rs`); only the coord-side log line and the run-loop
dispatch change.

### End-to-end falsifiable claim

A pipeline-shape NDJSON line, signed under a registered
tenant's key and gated through `verify_and_admit_pipeline`,
flows all the way through committee selection → assignment →
attestation aggregation → quorum verdict → Merkle anchor.
Witnessed live in `bins/cosaci-demo/src/bin/demo_networked.rs`'s
pass-3 stdin pipeline, with the `outcome Pass` log line on
`shape=pipeline step(s)=1` jobs. The CI smoke test's
`grep -q "shape=pipeline step(s)=1"` falsifies regression.

## Out of scope (follow-on)

- Per-step capability/resource enforcement at submission time.
  The current gate accepts any well-signed `pipeline_cbor`;
  step-level policy is enforced by the executor at run time
  (see `egress-policy-evaluation`, `resource-limit-enforcement`).
- Migration of existing v0.3 clients off the legacy
  `JobSubmissionPayload` shape — both shapes are accepted in
  parallel during the v0.4 → v0.5 transition.
- New step kinds beyond ExecWasm: tracked under #107
  (ExecNative cgroups sandbox) and #108 (CaptureLog +
  CaptureArtifact bundle).
