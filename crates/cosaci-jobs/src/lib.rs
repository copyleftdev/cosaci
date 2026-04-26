#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! `cosaci-jobs` — typed job-pipeline DSL.
//!
//! Source: `SPEC.md` §6.2 / `hypotheses/pipeline-determinism.md` (class A).
//!
//! A [`Pipeline`] is the unit of work the coordinator dispatches to a
//! committee. It's a sequence of [`Step`]s, each with typed inputs and
//! outputs, executed in order. The agent threads each step's
//! [`StepOutput::output_hash`] into the next step's input space, and
//! produces a [`PipelineResult`] whose `final_artifact_hash` is the
//! attestation's `artifact_hash`.
//!
//! # Determinism contract
//!
//! Two runners executing the same `Pipeline` against the same source
//! state must produce byte-equal `PipelineResult`s. This is the
//! property under `hypotheses/pipeline-determinism.md`; falsification
//! by the property test means a step's executor is reading
//! non-deterministic state (clock, randomness, network) without
//! attesting it.
//!
//! # v0.3 step coverage
//!
//! - [`Step::ExecWasm`] — implemented (delegates to `cosaci-wasm`).
//! - [`Step::SourceFetch`] — implemented (issue #40, shells out to
//!   `git`; falls back to `StepStatus::Failed` if `git` isn't on
//!   `PATH`). Tree hashing is the deterministic core under
//!   `hypotheses/source-fetch-determinism.md`.
//! - [`Step::ExecNative`] — types defined; executor + sandbox lands in
//!   issues #43 (resource limits) + #54 (egress policy).
//! - [`Step::CaptureLog`] / [`Step::CaptureArtifact`] — types defined;
//!   executors land alongside `ExecNative`.
//!
//! Calling [`execute_pipeline`] on a pipeline that contains an
//! unimplemented step type returns [`PipelineError::StepNotImplemented`]
//! — the type system permits it, the executor doesn't. This is
//! intentional: the wire shape is forward-compatible with all step
//! types, so a coordinator can construct a pipeline today that runs
//! once the executor lands without re-breaking the protocol.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub mod network;
pub mod source_fetch;
pub use network::NetworkPolicy;
pub use source_fetch::{SourceFetchError, SourceFetchOutput};

/// Fuel-units-per-cpu-second translation factor for WASM execution
/// (issue #43). One fuel unit ≈ one wasmtime instruction; modern x86
/// runs ~10⁹ simple WASM ops per second, so this gives roughly
/// wall-time-aligned cpu accounting for compute-bound modules. The
/// constant is conservative: I/O- or trap-bound modules will hit fuel
/// faster in wall-time terms than this implies. Documented + tested.
pub const FUEL_PER_CPU_SECOND: u64 = 1_000_000_000;

/// One pipeline = an ordered list of steps. Steps execute in order;
/// each step's `output_hash` is in the canonical input for the next
/// step.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pipeline {
    /// Ordered step list. Empty pipelines are valid (zero-step
    /// pipelines produce a `PipelineResult` with no step outputs and
    /// a `final_artifact_hash` that hashes the empty step list).
    pub steps: Vec<Step>,
}

/// A single pipeline step. The variant determines the executor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Step {
    /// Fetch source code from a git URL at a specific reference.
    /// Executor lands in issue #40; today this returns
    /// `PipelineError::StepNotImplemented`.
    SourceFetch {
        /// Git repository URL (https or ssh).
        url: String,
        /// Reference: commit SHA, tag, or branch name.
        reference: String,
    },
    /// Execute a WASM module with CBOR-encoded args. The module exports
    /// `add(i32, i32) -> i32` per the v0.2 ABI in `cosaci-wasm`.
    /// Implemented today.
    ExecWasm {
        /// The `.wasm` module bytes.
        module: Vec<u8>,
        /// CBOR-encoded `(i32, i32)` argument tuple.
        args_cbor: Vec<u8>,
        /// Resource limits for this step.
        limits: Limits,
    },
    /// Execute a native command with a fixed argv + environment.
    /// Executor lands in issue #43 (resource limits) + #54 (egress).
    ExecNative {
        /// Command + arguments. `command[0]` is the executable.
        command: Vec<String>,
        /// Environment variables for the child process. BTreeMap so
        /// canonical encoding is deterministic.
        env: BTreeMap<String, String>,
        /// Resource limits for this step.
        limits: Limits,
    },
    /// Capture logs from a previous step into the artifact bundle.
    /// Executor lands alongside `ExecNative`.
    CaptureLog {
        /// Logical name the captured log appears under in the
        /// artifact bundle.
        name: String,
    },
    /// Capture a file artifact produced by a previous step.
    /// Executor lands alongside `ExecNative`.
    CaptureArtifact {
        /// Filesystem path (relative to the step's working directory).
        path: String,
        /// Logical name the artifact appears under in the bundle.
        name: String,
    },
}

/// Resource limits enforced per step. Default is "no enforcement"; WASM
/// enforcement lands in issue #43, network egress in issue #54.
///
/// `Limits` is `Clone` (not `Copy`) because `network` carries an
/// allowlist `Vec`. Cloning is cheap for typical policies (a handful
/// of allowlist entries).
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Limits {
    /// CPU-time limit in seconds. `0` means unlimited (default).
    pub cpu_seconds: u32,
    /// Resident memory limit in MiB. `0` means unlimited (default).
    pub memory_mb: u32,
    /// Wall-clock limit in seconds. `0` means unlimited (default).
    pub wall_seconds: u32,
    /// Network egress policy. Default is "deny everything" (see
    /// [`NetworkPolicy::default`]); operators opt into specific
    /// targets via `network.allow`. Issue #54.
    pub network: NetworkPolicy,
}

/// Result of one step's execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepOutput {
    /// 0-indexed position of this step in the source pipeline.
    pub step_index: u32,
    /// Final state of the step.
    pub status: StepStatus,
    /// Content hash of the step's observable output. The next step's
    /// canonical input includes this value, so any divergence
    /// propagates forward.
    pub output_hash: [u8; 32],
}

/// Terminal state of a step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepStatus {
    /// Step completed normally.
    Success,
    /// Step ran but exited with a non-zero status / Err result.
    Failed,
    /// Step exceeded a resource limit. The variant encodes which
    /// limit; issue #43 wires real enforcement.
    LimitExceeded {
        /// Which limit was breached.
        which: LimitKind,
    },
    /// Step type's executor is not yet implemented in this build.
    /// Distinct from `Failed` so the coordinator can distinguish
    /// "the step ran and failed" from "the step couldn't run at all."
    NotImplemented,
}

/// Identifies which resource limit a step exceeded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LimitKind {
    /// CPU-time budget exhausted.
    Cpu,
    /// Memory budget exhausted.
    Memory,
    /// Wall-clock deadline reached.
    Wall,
    /// Network egress attempted against a denied policy.
    Network,
}

/// Aggregate output of an entire pipeline run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineResult {
    /// Per-step outputs, in pipeline order.
    pub steps: Vec<StepOutput>,
    /// SHA-256 of the canonical encoding of `steps`. This is the
    /// value that goes into the attestation's `artifact_hash`. Two
    /// runners producing different per-step output hashes produce
    /// different `final_artifact_hash`es, so committee disagreement
    /// surfaces at the quorum layer without needing per-step
    /// inspection.
    pub final_artifact_hash: [u8; 32],
}

/// Errors the pipeline executor can return.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PipelineError {
    /// CBOR encode/decode failure on a step's args or output.
    Encoding {
        /// Step index that produced the encoding error.
        step_index: u32,
        /// Human-readable detail.
        detail: String,
    },
    /// Underlying WASM runtime returned an error.
    WasmRuntime {
        /// Step index.
        step_index: u32,
        /// Detail from `cosaci-wasm`.
        detail: String,
    },
    /// The step type is defined in the DSL but its executor is not
    /// implemented in this build. See module-level docs for which
    /// step types execute today.
    StepNotImplemented {
        /// Step index.
        step_index: u32,
        /// Step kind that's not yet executable.
        kind: StepKind,
    },
}

/// Discriminant of [`Step`] used in error reporting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepKind {
    /// `Step::SourceFetch`
    SourceFetch,
    /// `Step::ExecWasm`
    ExecWasm,
    /// `Step::ExecNative`
    ExecNative,
    /// `Step::CaptureLog`
    CaptureLog,
    /// `Step::CaptureArtifact`
    CaptureArtifact,
}

/// SHA-256 of the canonical CBOR encoding of `value`.
fn hash_canonical<T: Serialize>(value: &T) -> [u8; 32] {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)
        .expect("ciborium encoding of well-formed serde types is infallible for this DSL");
    let mut h = Sha256::new();
    h.update(&buf);
    h.finalize().into()
}

/// Compute the canonical encoding of a pipeline. Two runners
/// constructing the same pipeline value always produce equal bytes;
/// this is the input the wire protocol carries.
///
/// # Errors
///
/// Returns [`PipelineError::Encoding`] if CBOR serialization fails
/// (in practice this never happens for the types this DSL defines).
pub fn canonical_encoding(pipeline: &Pipeline) -> Result<Vec<u8>, PipelineError> {
    let mut buf = Vec::new();
    ciborium::into_writer(pipeline, &mut buf).map_err(|e| PipelineError::Encoding {
        step_index: 0,
        detail: format!("cbor encode pipeline: {e}"),
    })?;
    Ok(buf)
}

/// Execute every step in `pipeline` in order and produce a
/// [`PipelineResult`].
///
/// For step types whose executor isn't yet implemented, the
/// corresponding `StepOutput` carries `StepStatus::NotImplemented` and
/// the step's `output_hash` is the canonical hash of its input. The
/// pipeline does not abort on `NotImplemented` — that lets a partially-
/// implemented coordinator return *something* deterministically while
/// downstream issues land.
///
/// # Errors
///
/// Returns the first [`PipelineError`] a step's executor produces.
/// CBOR-decode failures and WASM runtime errors propagate; the rest
/// are encoded as terminal `StepStatus` values.
pub fn execute_pipeline(pipeline: &Pipeline) -> Result<PipelineResult, PipelineError> {
    let mut step_outputs: Vec<StepOutput> = Vec::with_capacity(pipeline.steps.len());

    for (idx, step) in pipeline.steps.iter().enumerate() {
        let step_index = idx as u32;
        let output = match step {
            Step::ExecWasm {
                module,
                args_cbor,
                limits,
            } => execute_wasm_step(step_index, module, args_cbor, limits.clone(), step)?,
            Step::SourceFetch { url, reference } => {
                execute_source_fetch_step(step_index, url, reference, step)
            }
            Step::ExecNative { .. } => not_implemented(step_index, step, StepKind::ExecNative),
            Step::CaptureLog { .. } => not_implemented(step_index, step, StepKind::CaptureLog),
            Step::CaptureArtifact { .. } => {
                not_implemented(step_index, step, StepKind::CaptureArtifact)
            }
        };
        step_outputs.push(output);
    }

    let final_artifact_hash = hash_canonical(&step_outputs);
    Ok(PipelineResult {
        steps: step_outputs,
        final_artifact_hash,
    })
}

fn execute_source_fetch_step(
    step_index: u32,
    url: &str,
    reference: &str,
    step: &Step,
) -> StepOutput {
    match source_fetch::execute_source_fetch(url, reference) {
        Ok(out) => StepOutput {
            step_index,
            status: StepStatus::Success,
            output_hash: source_fetch::output_hash(&out),
        },
        Err(e) => {
            // Propagate as a Failed step with a deterministic
            // output_hash binding (step canonical bytes, error
            // discriminant). Two runners that hit the same
            // failure on the same step produce equal hashes.
            let detail = format!("source_fetch step {step_index} failed: {e}");
            let kind_id = match &e {
                SourceFetchError::GitNotFound => 0_u8,
                SourceFetchError::CloneFailed(_) => 1,
                SourceFetchError::CheckoutFailed(_) => 2,
                SourceFetchError::ResolveFailed(_) => 3,
                SourceFetchError::Io(_) => 4,
            };
            tracing_workaround_warn(&detail);
            StepOutput {
                step_index,
                status: StepStatus::Failed,
                output_hash: hash_canonical(&(step, kind_id)),
            }
        }
    }
}

/// Local stand-in for `tracing::warn!` since `cosaci-jobs` doesn't
/// pull `tracing` (keeps the lib `#![forbid(unsafe_code)]` deps
/// minimal). Writes to stderr; the coord's tracing fmt subscriber
/// captures it via `journalctl`.
fn tracing_workaround_warn(msg: &str) {
    eprintln!("[cosaci-jobs] {msg}");
}

fn execute_wasm_step(
    step_index: u32,
    module: &[u8],
    args_cbor: &[u8],
    limits: Limits,
    step: &Step,
) -> Result<StepOutput, PipelineError> {
    use cosaci_wasm::wasm_runtime::{ExecLimitKind, ExecLimits, ExecOutcome, execute_with_limits};

    let exec_limits = ExecLimits {
        fuel: u64::from(limits.cpu_seconds).saturating_mul(FUEL_PER_CPU_SECOND),
        memory_bytes: (limits.memory_mb as usize).saturating_mul(1024 * 1024),
        wall: Duration::from_secs(u64::from(limits.wall_seconds)),
    };

    let outcome = execute_with_limits(module, args_cbor, exec_limits).map_err(|e| {
        PipelineError::WasmRuntime {
            step_index,
            detail: e,
        }
    })?;

    match outcome {
        ExecOutcome::Ok(result) => {
            let module_hash = cosaci_wasm::wasm_runtime::module_hash(module);
            let output_hash = cosaci_wasm::wasm_runtime::output_hash(&module_hash, result);
            Ok(StepOutput {
                step_index,
                status: StepStatus::Success,
                output_hash,
            })
        }
        ExecOutcome::LimitExceeded(kind) => {
            let which = match kind {
                ExecLimitKind::Cpu => LimitKind::Cpu,
                ExecLimitKind::Memory => LimitKind::Memory,
                ExecLimitKind::Wall => LimitKind::Wall,
            };
            // Output hash for a limit-exceeded step binds (step bytes,
            // limit kind). Two runners that hit the same limit on the
            // same step produce the same hash; runners that didn't
            // hit the limit produce a `Success` hash that's distinct.
            Ok(StepOutput {
                step_index,
                status: StepStatus::LimitExceeded { which },
                output_hash: hash_canonical(&(step, which)),
            })
        }
    }
}

/// Construct a `StepOutput` for a step type whose executor isn't yet
/// implemented. The `output_hash` is the canonical hash of the step
/// itself — same step → same hash, deterministic across runners,
/// distinguishable from any future real execution result by the
/// `NotImplemented` status.
fn not_implemented(step_index: u32, step: &Step, _kind: StepKind) -> StepOutput {
    StepOutput {
        step_index,
        status: StepStatus::NotImplemented,
        output_hash: hash_canonical(step),
    }
}
