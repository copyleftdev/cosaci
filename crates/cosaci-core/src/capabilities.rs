//! Runner capabilities and job requirements.
//!
//! Source: `SPEC.md` §5.2b / `hypotheses/capability-match.md` (class A).
//! `matches(runner, job)` is the gate the scheduler consults before issuing
//! a lease. Pure predicate, no state.

use std::collections::HashSet;

/// Target operating-system + CPU architecture of a runner or job.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Platform {
    /// Linux on x86-64.
    LinuxX86_64,
    /// Linux on ARM64.
    LinuxAarch64,
    /// macOS on x86-64.
    DarwinX86_64,
    /// macOS on ARM64 (Apple silicon).
    DarwinAarch64,
}

/// Sandbox runtimes available on a runner or required by a job.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Runtime {
    /// In-process WebAssembly via wasmtime.
    Wasm,
    /// Microvm via Firecracker.
    Firecracker,
    /// OCI container via the Docker daemon.
    Docker,
}

/// What a runner offers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capabilities {
    /// Available CPU cores.
    pub cpu: u32,
    /// Available memory in MiB.
    pub memory_mb: u32,
    /// Host platform (OS + arch).
    pub platform: Platform,
    /// Sandbox runtimes the runner has installed.
    pub runtimes: HashSet<Runtime>,
}

/// What a job requires.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobRequirements {
    /// Minimum CPU cores the runner must offer.
    pub cpu: u32,
    /// Minimum memory in MiB.
    pub memory_mb: u32,
    /// Required platform (exact match).
    pub platform: Platform,
    /// Sandbox runtimes the job needs available.
    pub runtimes: HashSet<Runtime>,
}

/// True iff `runner` can run `job`:
///
/// - CPU and memory are `>=` comparisons (runner must have at least as much).
/// - Platform is exact equality (different arch or OS → no match).
/// - Runtimes are subset: `runner.runtimes ⊇ job.runtimes`.
#[must_use]
pub fn matches(runner: &Capabilities, job: &JobRequirements) -> bool {
    runner.cpu >= job.cpu
        && runner.memory_mb >= job.memory_mb
        && runner.platform == job.platform
        && job.runtimes.is_subset(&runner.runtimes)
}
