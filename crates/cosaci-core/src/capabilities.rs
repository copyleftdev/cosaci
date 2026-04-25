//! Runner capabilities and job requirements.
//!
//! Source: `SPEC.md` §5.2b / `hypotheses/capability-match.md` (class A) +
//! `hypotheses/capability-aware-committee.md` (issue #34, class A).
//! `matches(runner, job)` is the gate the scheduler consults before
//! including a runner in a job's committee. Pure predicate, no state.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// Target operating-system + CPU architecture of a runner or job.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
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
///
/// `Ord` derived so containers like `BTreeSet<Runtime>` produce
/// canonical CBOR encodings — required for the wire shape (every
/// runner encoding the same `Capabilities` must produce byte-equal
/// bytes, otherwise committee selection itself becomes
/// non-deterministic).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Runtime {
    /// In-process WebAssembly via wasmtime.
    Wasm,
    /// Microvm via Firecracker.
    Firecracker,
    /// OCI container via the Docker daemon.
    Docker,
}

/// What a runner offers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    /// Available CPU cores.
    pub cpu: u32,
    /// Available memory in MiB.
    pub memory_mb: u32,
    /// Host platform (OS + arch).
    pub platform: Platform,
    /// Sandbox runtimes the runner has installed. `BTreeSet` for
    /// canonical CBOR encoding on the wire.
    pub runtimes: BTreeSet<Runtime>,
}

/// What a job requires.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobRequirements {
    /// Minimum CPU cores the runner must offer.
    pub cpu: u32,
    /// Minimum memory in MiB.
    pub memory_mb: u32,
    /// Required platform (exact match).
    pub platform: Platform,
    /// Sandbox runtimes the job needs available.
    pub runtimes: BTreeSet<Runtime>,
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

/// One candidate for committee membership: a runner with its
/// declared capabilities and the VRF output it produced for the
/// job seed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate<Id: Copy + Eq> {
    /// Identifier of the candidate runner.
    pub id: Id,
    /// What the runner declared at registration.
    pub capabilities: Capabilities,
    /// The runner's VRF output for the current job seed.
    pub vrf_output: [u8; 32],
}

/// Select a committee of `committee_size` runners that satisfy
/// `requirements`, ranked by VRF output (lex-min).
///
/// Returns `None` when fewer than `committee_size` candidates match
/// `requirements` — the coordinator must not silently form an
/// undersized committee. Issue #34's hypothesis card
/// `capability-aware-committee` documents the soundness +
/// completeness + underprovisioning-honesty + filter-then-rank
/// properties; the contract is enforced here so callers don't have
/// to reimplement the logic.
#[must_use]
pub fn select_capability_aware_committee<Id: Copy + Eq>(
    candidates: &[Candidate<Id>],
    requirements: &JobRequirements,
    committee_size: usize,
) -> Option<Vec<Id>> {
    let mut eligible: Vec<&Candidate<Id>> = candidates
        .iter()
        .filter(|c| matches(&c.capabilities, requirements))
        .collect();
    if eligible.len() < committee_size {
        return None;
    }
    eligible.sort_by(|a, b| a.vrf_output.cmp(&b.vrf_output));
    Some(
        eligible
            .into_iter()
            .take(committee_size)
            .map(|c| c.id)
            .collect(),
    )
}
