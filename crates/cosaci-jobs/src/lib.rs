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
//! - [`Step::ExecNative`] — executor implemented through #107 PR 3
//!   of N: plain spawn + walltime + bounded captures (PR 1),
//!   cgroup-v2 `memory.max` + OOM-kill detection (PR 2), polled
//!   `cpu.stat::usage_usec` enforcement of `cpu_seconds` (PR 3).
//!   **Remaining sandbox layers**: mount-namespace + read-only
//!   rootfs (PR 4), egress enforcement (PR 5). See
//!   `hypotheses/exec-native-determinism.md`.
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
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
    /// Plain executor: #107 PR 1; cgroups v2 memory: PR 2;
    /// cgroups v2 cpu (polled): PR 3. Mount-namespace + egress:
    /// PRs 4-5.
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
    /// Per-step captures emitted by [`Step::CaptureLog`] or
    /// [`Step::CaptureArtifact`] (#108). **Not** part of
    /// `final_artifact_hash` — the canonical attestation hash
    /// binds only `steps`, so capture payload size doesn't
    /// shift the hash and capture/no-capture pipelines remain
    /// committee-comparable.
    ///
    /// Skipped at serialization when empty; an existing
    /// pre-#108 producer that emits no captures yields the
    /// same wire bytes as before.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub captures: Vec<CapturedOutput>,
}

/// One captured payload emitted by a `CaptureLog` /
/// `CaptureArtifact` step. The bytes travel alongside the
/// signed `Attestation` in the wire-level `AttestationBundle`
/// (lands in a follow-on PR); on the agent side they live in
/// [`PipelineResult::captures`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturedOutput {
    /// 0-indexed position of the capture **step** in the
    /// pipeline (the `Step::CaptureLog` step itself, not the
    /// step whose output is being captured).
    pub step_index: u32,
    /// Operator-chosen handle from the `Step`'s `name` field;
    /// stdout/stderr captures append `.stdout`/`.stderr` to
    /// disambiguate.
    pub name: String,
    /// What kind of bytes this carries.
    pub kind: CaptureKind,
    /// SHA-256 of the captured bytes (post-truncation if a
    /// cap was applied — the hash matches the bytes inline).
    pub sha256: [u8; 32],
    /// Total length of the original output before any
    /// truncation. May exceed `bytes_inline.len()` if a cap
    /// was applied; the difference is observable.
    pub length: u64,
    /// Captured bytes, up to the per-step `max_log_bytes`
    /// cap. If the original output exceeded the cap, this
    /// holds the prefix only.
    pub bytes_inline: Vec<u8>,
}

/// Kind of capture in a [`CapturedOutput`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaptureKind {
    /// Captured stdout from a `Step::ExecNative`.
    Stdout,
    /// Captured stderr from a `Step::ExecNative`.
    Stderr,
    /// Captured file artifact (lands with `Step::CaptureArtifact`).
    Artifact,
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
    let mut captures: Vec<CapturedOutput> = Vec::new();
    // Holds the most recent `Step::ExecNative`'s captured
    // stdout/stderr so a following `Step::CaptureLog` can
    // emit them. Reset whenever a new ExecNative runs;
    // unrelated step types (ExecWasm, SourceFetch) don't
    // touch it. None means "no preceding ExecNative".
    let mut last_native: Option<NativeCaptures> = None;

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
            Step::ExecNative {
                command,
                env,
                limits,
            } => {
                let (out, native_caps) =
                    execute_native_step(step_index, command, env, limits, step);
                last_native = Some(native_caps);
                out
            }
            Step::CaptureLog { name } => execute_capture_log_step(
                step_index,
                name,
                last_native.as_ref(),
                &mut captures,
                step,
            ),
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
        captures,
    })
}

/// Captured bytes from one `Step::ExecNative`. Lives
/// in-memory between the ExecNative step and any following
/// `Step::CaptureLog`. Holds full bytes (already capped at
/// `MAX_CAPTURE_BYTES` by the executor) plus the stable
/// SHA-256 each pipe was bound to in the ExecNative's
/// `output_hash`.
struct NativeCaptures {
    stdout_bytes: Vec<u8>,
    stdout_sha256: [u8; 32],
    stderr_bytes: Vec<u8>,
    stderr_sha256: [u8; 32],
}

/// Executor for `Step::CaptureLog`. Reads the most recent
/// `Step::ExecNative`'s stdout + stderr (if any) and emits
/// two `CapturedOutput` records, named `<name>.stdout` and
/// `<name>.stderr`. With no preceding ExecNative, the step
/// is `Failed` deterministically — no bytes to capture.
fn execute_capture_log_step(
    step_index: u32,
    name: &str,
    last_native: Option<&NativeCaptures>,
    captures: &mut Vec<CapturedOutput>,
    step: &Step,
) -> StepOutput {
    let Some(nc) = last_native else {
        let detail = format!(
            "capture_log step {step_index} ('{name}'): no preceding ExecNative; nothing to capture"
        );
        tracing_workaround_warn(&detail);
        return StepOutput {
            step_index,
            status: StepStatus::Failed,
            output_hash: hash_canonical(&(step, "no_preceding_exec_native")),
        };
    };

    captures.push(CapturedOutput {
        step_index,
        name: format!("{name}.stdout"),
        kind: CaptureKind::Stdout,
        sha256: nc.stdout_sha256,
        length: nc.stdout_bytes.len() as u64,
        bytes_inline: nc.stdout_bytes.clone(),
    });
    captures.push(CapturedOutput {
        step_index,
        name: format!("{name}.stderr"),
        kind: CaptureKind::Stderr,
        sha256: nc.stderr_sha256,
        length: nc.stderr_bytes.len() as u64,
        bytes_inline: nc.stderr_bytes.clone(),
    });

    // Hash binds the step + the two source hashes. Two
    // runners that observed the same ExecNative output and
    // the same `name` produce the same CaptureLog
    // output_hash; bytes themselves don't go in the hash
    // (they're already bound transitively through the
    // ExecNative step's `output_hash`).
    StepOutput {
        step_index,
        status: StepStatus::Success,
        output_hash: hash_canonical(&(step, "ok", nc.stdout_sha256, nc.stderr_sha256)),
    }
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

/// Cap on captured stdout/stderr per step. Native processes that
/// emit more than this are truncated (the first
/// `MAX_CAPTURE_BYTES` are hashed; the remainder is drained from
/// the pipe but not retained, so the child doesn't block).
/// Matches `MAX_ENVELOPE_BYTES_PUB`'s 16 MiB shape — the next
/// hop is the wire envelope, so capping here avoids a second
/// truncation downstream.
const MAX_CAPTURE_BYTES: usize = 16 * 1024 * 1024;

/// How often the wall-timeout watchdog polls `try_wait`. 50ms
/// bounds the lateness of a kill at ~50ms past `wall_seconds`,
/// which is well below any realistic step-level deadline.
const WALL_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Execute one `Step::ExecNative`.
///
/// **Plain executor — no sandbox** (issue #107 PR 1 of N). The
/// child runs as the parent's UID/GID with whatever capabilities
/// the parent has. cgroups limits, mount namespaces, and egress
/// enforcement land in subsequent PRs (#107 PR 2/3/4).
///
/// What this PR enforces:
///
/// - **wall_seconds** — a watchdog polls `try_wait` every
///   [`WALL_POLL_INTERVAL`]; if the child is still running after
///   `wall_seconds`, it gets `kill()` and the step terminates as
///   `LimitExceeded { Wall }`.
/// - **Bounded captures** — stdout and stderr are read by
///   per-pipe threads up to [`MAX_CAPTURE_BYTES`]; bytes past the
///   cap are drained without retention so the child doesn't
///   block on pipe back-pressure.
/// - **Deterministic hash** — the `output_hash` binds (step
///   bytes, status, exit_code, stdout SHA-256, stderr SHA-256).
///   Two runners that execute the same command with the same
///   environment and observe the same exit + bytes produce the
///   same hash. Walltime and PID are not in the hash.
///
/// What this PR does **not** enforce:
///
/// - cpu_seconds / memory_mb — both ignored. Setting them is
///   currently a no-op; cgroups v2 wiring lands in #107 PR 2.
/// - Filesystem isolation — the child sees the parent's full
///   filesystem.
/// - Environment leakage — `env_clear()` runs first, so the
///   child only sees the explicit `env` map. PATH is not
///   inherited; the caller must include it if the executable
///   isn't an absolute path.
fn execute_native_step(
    step_index: u32,
    command: &[String],
    env: &BTreeMap<String, String>,
    limits: &Limits,
    step: &Step,
) -> (StepOutput, NativeCaptures) {
    let empty_sha256: [u8; 32] = Sha256::digest([]).into();
    let empty_caps = || NativeCaptures {
        stdout_bytes: Vec::new(),
        stdout_sha256: empty_sha256,
        stderr_bytes: Vec::new(),
        stderr_sha256: empty_sha256,
    };
    if command.is_empty() {
        let detail = format!("native step {step_index}: empty command");
        tracing_workaround_warn(&detail);
        return (
            StepOutput {
                step_index,
                status: StepStatus::Failed,
                output_hash: hash_canonical(&(step, "empty_command")),
            },
            empty_caps(),
        );
    }

    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..]);
    cmd.env_clear();
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let detail = format!("native step {step_index}: spawn failed: {e}");
            tracing_workaround_warn(&detail);
            // Spawn-failure hash binds (step, e.kind()) so
            // identical "command not found" failures hash equally
            // across runners but distinct from a successful run.
            let kind_id = e.kind() as i32;
            return (
                StepOutput {
                    step_index,
                    status: StepStatus::Failed,
                    output_hash: hash_canonical(&(step, "spawn_failed", kind_id)),
                },
                empty_caps(),
            );
        }
    };

    // cgroup-v2 enforcement (#107 PR 2/3 of N). Attach the child
    // to a per-step sub-cgroup with `memory.max` set (PR 2) and
    // observe `cpu.stat::usage_usec` for cpu_seconds enforcement
    // (PR 3). Setup failures (no cgroup-v2, no user delegation,
    // no memory/cpu controllers in subtree) make `try_create`
    // return `None` and the step runs without those layers
    // (matches PR-1 semantics).
    let cgroup = StepCgroup::try_create(step_index, limits.memory_mb, limits.cpu_seconds);
    if let Some(cg) = cgroup.as_ref() {
        if let Err(e) = cg.attach(child.id()) {
            tracing_workaround_warn(&format!(
                "native step {step_index}: cgroup attach failed: {e}; step continues without cgroup enforcement"
            ));
        }
    }

    let stdout_pipe = child.stdout.take().expect("stdout piped");
    let stderr_pipe = child.stderr.take().expect("stderr piped");
    let stdout_thread = thread::spawn(move || read_capped(stdout_pipe, MAX_CAPTURE_BYTES));
    let stderr_thread = thread::spawn(move || read_capped(stderr_pipe, MAX_CAPTURE_BYTES));

    // Multi-limit wait. Wall-time uses the elapsed `Instant` from
    // call entry; cpu_seconds uses the cgroup's `cpu.stat::
    // usage_usec` (only if a cgroup with the cpu controller was
    // successfully created — same graceful-fallback story as
    // memory).
    let wall_limit =
        (limits.wall_seconds > 0).then(|| Duration::from_secs(u64::from(limits.wall_seconds)));
    let cpu_limit =
        (limits.cpu_seconds > 0).then(|| Duration::from_secs(u64::from(limits.cpu_seconds)));
    let outcome = wait_with_limits(&mut child, wall_limit, cpu_limit, cgroup.as_ref());

    // Read OOM state BEFORE the cgroup is dropped (StepCgroup's
    // Drop calls rmdir, which clears memory.events.local). Cheap
    // file read; safe to do whether or not setup succeeded.
    let oom_killed = cgroup.as_ref().is_some_and(StepCgroup::was_oom_killed);

    match outcome {
        ExitOutcome::Exited(status) => {
            // Clean exit — wait for reader threads to drain. Since
            // the child's pipes close on exit, both reads EOF
            // promptly.
            let stdout = stdout_thread.join().unwrap_or_default();
            let stderr = stderr_thread.join().unwrap_or_default();
            let stdout_hash: [u8; 32] = Sha256::digest(&stdout).into();
            let stderr_hash: [u8; 32] = Sha256::digest(&stderr).into();
            // Memory cap exceeded (cgroup OOM-kill). Attribute
            // even if the kernel signaled the child as a normal
            // SIGKILL — the cgroup's `oom_kill` counter is the
            // ground truth. The hash binds only
            // (step, LimitKind::Memory); captures emit as
            // `empty_caps()` for symmetry with the wall/cpu
            // paths (partial output before OOM isn't a
            // determinism contract we want to take on).
            if oom_killed {
                return (
                    StepOutput {
                        step_index,
                        status: StepStatus::LimitExceeded {
                            which: LimitKind::Memory,
                        },
                        output_hash: hash_canonical(&(step, LimitKind::Memory)),
                    },
                    empty_caps(),
                );
            }
            let caps = NativeCaptures {
                stdout_bytes: stdout,
                stdout_sha256: stdout_hash,
                stderr_bytes: stderr,
                stderr_sha256: stderr_hash,
            };
            let out = if status.success() {
                StepOutput {
                    step_index,
                    status: StepStatus::Success,
                    output_hash: hash_canonical(&(
                        step,
                        "ok",
                        status.code().unwrap_or(0),
                        stdout_hash,
                        stderr_hash,
                    )),
                }
            } else {
                let code = status.code().unwrap_or(-1);
                StepOutput {
                    step_index,
                    status: StepStatus::Failed,
                    output_hash: hash_canonical(&(
                        step,
                        "exit_nonzero",
                        code,
                        stdout_hash,
                        stderr_hash,
                    )),
                }
            };
            (out, caps)
        }
        ExitOutcome::KilledByWall | ExitOutcome::KilledByCpu => {
            // Limit exceeded; child was killed by us. We do NOT
            // `join` the reader threads here. Rationale: if the
            // killed child had spawned its own children (e.g.
            // `sh -c 'sleep 5'` reparents `sleep` to init), those
            // children inherit our stdout/stderr pipes and the
            // pipe-read won't EOF until they exit. Joining would
            // block past the limit. The output_hash for these
            // cases binds only (step, LimitKind) — captured
            // bytes are intentionally not part of the hash, so
            // dropping them here keeps determinism intact. The
            // detached reader threads finish when the reparented
            // children close their pipe ends, after which they
            // exit cleanly. PR 4 (cgroups + namespaces) replaces
            // this with a cgroup-kill of the whole process tree.
            drop(stdout_thread);
            drop(stderr_thread);
            let which = match outcome {
                ExitOutcome::KilledByWall => LimitKind::Wall,
                ExitOutcome::KilledByCpu => LimitKind::Cpu,
                ExitOutcome::Exited(_) => unreachable!(),
            };
            (
                StepOutput {
                    step_index,
                    status: StepStatus::LimitExceeded { which },
                    output_hash: hash_canonical(&(step, which)),
                },
                empty_caps(),
            )
        }
    }
}

/// Outcome of waiting on the child with optional walltime +
/// cpu-time limits. Distinguishes a clean exit from a kill we
/// initiated (so the caller can attribute the right
/// `LimitKind`).
enum ExitOutcome {
    Exited(std::process::ExitStatus),
    KilledByWall,
    KilledByCpu,
}

/// Per-step cgroup-v2 sandbox (#107 PR 2/3 of N — memory hard
/// cap + cpu-time observation).
///
/// On Linux with cgroup-v2 + user delegation:
///
/// 1. Resolve the calling process's cgroup from `/proc/self/cgroup`.
/// 2. Create a unique sub-cgroup under it.
/// 3. Write `memory.max` = `memory_mb << 20` bytes (PR 2).
/// 4. Caller attaches the child via [`Self::attach`].
/// 5. While the child runs, the caller may poll
///    [`Self::cpu_usage_usec`] to enforce `cpu_seconds`
///    (PR 3 — cgroup `cpu.max` is a rate limiter, not a
///    cumulative-time killer, so total-time enforcement
///    requires polling).
/// 6. After the child exits, [`Self::was_oom_killed`] reads
///    `memory.events.local` to detect kernel OOM-kill.
/// 6. `Drop` rmdirs the sub-cgroup (best-effort).
///
/// On non-Linux platforms or when cgroup-v2 / delegation isn't
/// available, [`Self::try_create`] returns `None` and the step
/// runs with no memory enforcement (matches PR-1 semantics).
///
/// Race window: between `Command::spawn` and
/// `attach(child.id())`, the child runs uncgrouped. For workloads
/// that allocate >memory_mb in <1ms, this could let the parent
/// machine's OOM-killer fire before the cgroup is in effect. PR 3
/// or later may close this with `clone3(CLONE_INTO_CGROUP)`,
/// which atomically places the new task into the target cgroup.
struct StepCgroup {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    path: PathBuf,
}

impl StepCgroup {
    /// Try to create a per-step cgroup. Returns `None` if no
    /// limits are requested (`memory_mb == 0 && cpu_seconds == 0`)
    /// or if any part of the cgroup setup fails. Each requested
    /// limit independently requires its controller in
    /// `cgroup.subtree_control`: memory needs `memory`, cpu
    /// needs `cpu`. Partial setup (e.g. memory delegated but cpu
    /// not, with cpu_seconds > 0) returns `None` for the whole
    /// step rather than silently honoring only one limit.
    #[cfg(target_os = "linux")]
    fn try_create(step_index: u32, memory_mb: u32, cpu_seconds: u32) -> Option<Self> {
        if memory_mb == 0 && cpu_seconds == 0 {
            return None;
        }
        let parent = current_cgroup_path()?;

        if memory_mb > 0 && !subtree_has_controller(&parent, "memory") {
            tracing_workaround_warn(&format!(
                "cgroup at {} doesn't delegate the memory controller; step {step_index} runs without memory enforcement",
                parent.display()
            ));
            return None;
        }
        if cpu_seconds > 0 && !subtree_has_controller(&parent, "cpu") {
            tracing_workaround_warn(&format!(
                "cgroup at {} doesn't delegate the cpu controller; step {step_index} runs without cpu enforcement",
                parent.display()
            ));
            return None;
        }

        // Unique sub-cgroup name. PID + step_index +
        // monotonic ns means concurrent steps in the same
        // process don't collide.
        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let name = format!("cosaci-step-{}-{step_index}-{now_ns}", std::process::id());
        let path = parent.join(name);

        if let Err(e) = std::fs::create_dir(&path) {
            tracing_workaround_warn(&format!(
                "cgroup mkdir at {} failed: {e}; step {step_index} runs without cgroup enforcement",
                path.display()
            ));
            return None;
        }

        if memory_mb > 0 {
            let mem_max = u64::from(memory_mb).saturating_mul(1024 * 1024);
            if let Err(e) = std::fs::write(path.join("memory.max"), mem_max.to_string()) {
                tracing_workaround_warn(&format!(
                    "cgroup memory.max write failed: {e}; cleaning up"
                ));
                let _ = std::fs::remove_dir(&path);
                return None;
            }
        }
        // cpu_seconds enforcement is observation-only at the
        // cgroup layer (see `cpu_usage_usec` + the executor's
        // wait_with_limits poll loop). Total-CPU-time is not
        // a kernel-enforced cgroup primitive — `cpu.max` is a
        // bandwidth (rate) limiter, not a cumulative-time
        // killer.

        Some(Self { path })
    }

    #[cfg(not(target_os = "linux"))]
    #[allow(dead_code)]
    fn try_create(_step_index: u32, _memory_mb: u32, _cpu_seconds: u32) -> Option<Self> {
        None
    }

    /// Attach the given PID to this cgroup. Writing to
    /// `cgroup.procs` migrates the entire thread-group of `pid`.
    #[cfg(target_os = "linux")]
    fn attach(&self, pid: u32) -> std::io::Result<()> {
        std::fs::write(self.path.join("cgroup.procs"), pid.to_string())
    }

    #[cfg(not(target_os = "linux"))]
    fn attach(&self, _pid: u32) -> std::io::Result<()> {
        Ok(())
    }

    /// True iff the kernel recorded an `oom_kill` event for
    /// this cgroup (i.e. memory.max was exceeded and the
    /// kernel's cgroup-OOM killer fired).
    #[cfg(target_os = "linux")]
    fn was_oom_killed(&self) -> bool {
        let Ok(text) = std::fs::read_to_string(self.path.join("memory.events.local")) else {
            return false;
        };
        text.lines()
            .filter_map(|line| line.strip_prefix("oom_kill "))
            .any(|rest| rest.trim().parse::<u64>().is_ok_and(|n| n > 0))
    }

    #[cfg(not(target_os = "linux"))]
    fn was_oom_killed(&self) -> bool {
        false
    }

    /// Cumulative CPU time used by all tasks in this cgroup,
    /// in microseconds. Reads `cpu.stat`'s `usage_usec` line —
    /// cgroup-v2's standard cpu accounting interface, present
    /// whenever the cpu controller is delegated. Returns
    /// `None` on any read or parse failure (including the
    /// stub on non-Linux).
    #[cfg(target_os = "linux")]
    fn cpu_usage_usec(&self) -> Option<u64> {
        let text = std::fs::read_to_string(self.path.join("cpu.stat")).ok()?;
        text.lines()
            .find_map(|line| line.strip_prefix("usage_usec "))
            .and_then(|rest| rest.trim().parse::<u64>().ok())
    }

    #[cfg(not(target_os = "linux"))]
    fn cpu_usage_usec(&self) -> Option<u64> {
        None
    }
}

impl Drop for StepCgroup {
    fn drop(&mut self) {
        // Best-effort. If the cgroup still has live processes
        // (rare — child has exited by this point), rmdir
        // returns EBUSY and we skip. The leaked cgroup is
        // auto-reclaimed by systemd when the parent scope ends.
        #[cfg(target_os = "linux")]
        {
            let _ = std::fs::remove_dir(&self.path);
        }
    }
}

/// Resolve the calling process's cgroup-v2 absolute path on
/// the unified hierarchy. Returns `None` on cgroup-v1, hybrid
/// systems, or read failure.
#[cfg(target_os = "linux")]
fn current_cgroup_path() -> Option<PathBuf> {
    let text = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    // cgroup-v2 unified hierarchy: a single line of the form
    // `0::<absolute-path>`. cgroup-v1 lines are `<id>:<controller>:<path>`.
    // We require the v2 line.
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("0::") {
            return Some(Path::new("/sys/fs/cgroup").join(rest.trim_start_matches('/')));
        }
    }
    None
}

/// True iff `cgroup_path/cgroup.subtree_control` enables the
/// named controller on its children. Without subtree
/// delegation, writing to `memory.max` etc. silently no-ops.
#[cfg(target_os = "linux")]
fn subtree_has_controller(cgroup_path: &Path, controller: &str) -> bool {
    let Ok(text) = std::fs::read_to_string(cgroup_path.join("cgroup.subtree_control")) else {
        return false;
    };
    text.split_whitespace().any(|c| c == controller)
}

/// Read up to `cap` bytes from `pipe`; drain the rest without
/// retaining so the child doesn't block on pipe back-pressure.
/// Returns the captured prefix.
fn read_capped<R: Read>(mut pipe: R, cap: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(cap.min(64 * 1024));
    let mut scratch = [0_u8; 8192];
    let mut total = 0_usize;
    loop {
        match pipe.read(&mut scratch) {
            Ok(0) => break,
            Ok(n) => {
                if total < cap {
                    let take = (cap - total).min(n);
                    out.extend_from_slice(&scratch[..take]);
                }
                total = total.saturating_add(n);
            }
            Err(_) => break,
        }
    }
    out
}

/// Wait for `child` with optional walltime + cpu-time limits.
///
/// On every poll iteration:
/// - `try_wait` checks for clean exit;
/// - `start.elapsed()` is compared against `wall_limit`;
/// - if `cpu_limit` and `cgroup` are both `Some`, the cgroup's
///   `cpu.stat::usage_usec` is read and compared.
///
/// First limit hit wins: child is `kill()`-ed + reaped, and the
/// matching [`ExitOutcome::KilledByWall`] / `KilledByCpu` is
/// returned. Both limits absent (or missing cgroup for cpu)
/// degrade to a plain blocking wait.
fn wait_with_limits(
    child: &mut std::process::Child,
    wall_limit: Option<Duration>,
    cpu_limit: Option<Duration>,
    cgroup: Option<&StepCgroup>,
) -> ExitOutcome {
    // Fast path: no limits, no cgroup → plain blocking wait
    // (no polling overhead).
    if wall_limit.is_none() && cpu_limit.is_none() {
        return match child.wait() {
            Ok(status) => ExitOutcome::Exited(status),
            Err(_) => ExitOutcome::KilledByWall, // unreachable in practice
        };
    }
    let start = Instant::now();
    let cpu_limit_usec = cpu_limit.map(|d| d.as_micros() as u64);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return ExitOutcome::Exited(status),
            Ok(None) => {}
            Err(_) => return ExitOutcome::KilledByWall,
        }
        if let Some(w) = wall_limit
            && start.elapsed() >= w
        {
            let _ = child.kill();
            let _ = child.wait();
            return ExitOutcome::KilledByWall;
        }
        if let (Some(c), Some(cg)) = (cpu_limit_usec, cgroup)
            && let Some(usage) = cg.cpu_usage_usec()
            && usage >= c
        {
            let _ = child.kill();
            let _ = child.wait();
            return ExitOutcome::KilledByCpu;
        }
        thread::sleep(WALL_POLL_INTERVAL);
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
