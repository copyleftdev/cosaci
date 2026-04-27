---
id: pipeline-submission
source: SPEC.md §13 (v0.5 lift) / SPEC.md §6.2
class: A
status: passing
test: tests/submission_auth_gate.rs
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

## Out of scope (follow-on)

- Coord-side `Pipeline` decode + execution wiring. Tracked
  under `pipeline-determinism` (passing, #39) and the v0.5
  execution issues (#107 ExecNative cgroups sandbox, #108
  CaptureLog + CaptureArtifact bundle).
- Per-step capability/resource enforcement at submission time.
  The current gate accepts any well-signed `pipeline_cbor`;
  step-level policy is enforced by the executor at run time
  (see `egress-policy-evaluation`, `resource-limit-enforcement`).
- Migration of existing v0.3 clients off the legacy
  `JobSubmissionPayload` shape — both shapes are accepted in
  parallel during the v0.4 → v0.5 transition.
