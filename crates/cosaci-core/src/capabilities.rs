//! Runner capabilities and job requirements.
//!
//! Source: `SPEC.md` §5.2b / `hypotheses/capability-match.md` (class A).
//! `matches(runner, job)` is the gate the scheduler consults before issuing
//! a lease. Pure predicate, no state.

use std::collections::HashSet;

/// Target operating-system + CPU architecture of a runner or job.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Platform {
    LinuxX86_64,
    LinuxAarch64,
    DarwinX86_64,
    DarwinAarch64,
}

/// Sandbox runtimes available on a runner or required by a job.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Runtime {
    Wasm,
    Firecracker,
    Docker,
}

/// What a runner offers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub cpu: u32,
    pub memory_mb: u32,
    pub platform: Platform,
    pub runtimes: HashSet<Runtime>,
}

/// What a job requires.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobRequirements {
    pub cpu: u32,
    pub memory_mb: u32,
    pub platform: Platform,
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
