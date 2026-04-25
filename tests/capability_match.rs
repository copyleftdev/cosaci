//! Property-based tests for `cosaci::capabilities::matches`.
//!
//! Encodes the falsifiable claims of `hypotheses/capability-match.md`
//! (SPEC.md §5.2b, class A).

use std::collections::BTreeSet;

use cosaci::capabilities::{Capabilities, JobRequirements, Platform, Runtime, matches};
use hegel::{TestCase, generators};

// ----------------------------------------------------------------------------
// Draw helpers
// ----------------------------------------------------------------------------

const PLATFORMS: [Platform; 4] = [
    Platform::LinuxX86_64,
    Platform::LinuxAarch64,
    Platform::DarwinX86_64,
    Platform::DarwinAarch64,
];

const RUNTIMES: [Runtime; 3] = [Runtime::Wasm, Runtime::Firecracker, Runtime::Docker];

fn draw_platform(tc: &TestCase) -> Platform {
    let i = tc.draw(generators::integers::<usize>().min_value(0).max_value(3));
    PLATFORMS[i]
}

fn draw_runtime(tc: &TestCase) -> Runtime {
    let i = tc.draw(generators::integers::<usize>().min_value(0).max_value(2));
    RUNTIMES[i]
}

fn draw_runtime_set(tc: &TestCase) -> BTreeSet<Runtime> {
    let mut s = BTreeSet::new();
    for r in RUNTIMES {
        if tc.draw(generators::booleans()) {
            s.insert(r);
        }
    }
    s
}

fn draw_capabilities(tc: &TestCase) -> Capabilities {
    Capabilities {
        cpu: tc.draw(generators::integers::<u32>().min_value(0).max_value(128)),
        memory_mb: tc.draw(
            generators::integers::<u32>()
                .min_value(0)
                .max_value(131_072),
        ),
        platform: draw_platform(tc),
        runtimes: draw_runtime_set(tc),
    }
}

fn draw_job(tc: &TestCase) -> JobRequirements {
    JobRequirements {
        cpu: tc.draw(generators::integers::<u32>().min_value(0).max_value(128)),
        memory_mb: tc.draw(
            generators::integers::<u32>()
                .min_value(0)
                .max_value(131_072),
        ),
        platform: draw_platform(tc),
        runtimes: draw_runtime_set(tc),
    }
}

// ----------------------------------------------------------------------------
// Property 1 — reflexive.
// A runner always matches a job whose requirements are taken from its own
// capabilities.
// ----------------------------------------------------------------------------
#[hegel::test]
fn match_is_reflexive(tc: hegel::TestCase) {
    let caps = draw_capabilities(&tc);
    let job = JobRequirements {
        cpu: caps.cpu,
        memory_mb: caps.memory_mb,
        platform: caps.platform,
        runtimes: caps.runtimes.clone(),
    };
    assert!(matches(&caps, &job), "reflexive match failed");
}

// ----------------------------------------------------------------------------
// Property 2 — monotone in capabilities.
// If baseline matches, strengthening the runner (more CPU, more memory, more
// runtimes; platform unchanged) must still match.
// ----------------------------------------------------------------------------
#[hegel::test]
fn match_monotone_in_capabilities(tc: hegel::TestCase) {
    let base = draw_capabilities(&tc);
    let job = draw_job(&tc);
    let baseline = matches(&base, &job);

    let extra_cpu = tc.draw(generators::integers::<u32>().min_value(0).max_value(64));
    let extra_mem = tc.draw(generators::integers::<u32>().min_value(0).max_value(65_536));
    let extra_runtime = draw_runtime(&tc);

    let mut stronger = base.clone();
    stronger.cpu = stronger.cpu.saturating_add(extra_cpu);
    stronger.memory_mb = stronger.memory_mb.saturating_add(extra_mem);
    stronger.runtimes.insert(extra_runtime);

    if baseline {
        assert!(
            matches(&stronger, &job),
            "strengthening runner capabilities unmatched a job"
        );
    }
}

// ----------------------------------------------------------------------------
// Property 3 — anti-monotone in requirements.
// If baseline matches, loosening the job (less CPU required, less memory,
// fewer runtimes; platform unchanged) must still match.
// ----------------------------------------------------------------------------
#[hegel::test]
fn match_antimonotone_in_requirements(tc: hegel::TestCase) {
    let caps = draw_capabilities(&tc);
    let job = draw_job(&tc);
    let baseline = matches(&caps, &job);

    let cpu_drop = tc.draw(
        generators::integers::<u32>()
            .min_value(0)
            .max_value(job.cpu),
    );
    let mem_drop = tc.draw(
        generators::integers::<u32>()
            .min_value(0)
            .max_value(job.memory_mb),
    );

    let mut easier = job.clone();
    easier.cpu -= cpu_drop;
    easier.memory_mb -= mem_drop;
    if !easier.runtimes.is_empty() && tc.draw(generators::booleans()) {
        // Optionally drop one required runtime.
        let any: Runtime = *easier
            .runtimes
            .iter()
            .next()
            .expect("nonempty checked above");
        easier.runtimes.remove(&any);
    }

    if baseline {
        assert!(
            matches(&caps, &easier),
            "loosening job requirements unmatched a runner"
        );
    }
}

// ----------------------------------------------------------------------------
// Property 4 — platform is exact match.
// Different platforms → never match, regardless of other fields.
// ----------------------------------------------------------------------------
#[hegel::test]
fn mismatched_platform_never_matches(tc: hegel::TestCase) {
    let mut caps = draw_capabilities(&tc);
    let mut job = draw_job(&tc);

    let caps_idx = tc.draw(generators::integers::<usize>().min_value(0).max_value(3));
    caps.platform = PLATFORMS[caps_idx];
    let mut job_idx = tc.draw(generators::integers::<usize>().min_value(0).max_value(3));
    if PLATFORMS[job_idx] == caps.platform {
        job_idx = (job_idx + 1) % 4;
    }
    job.platform = PLATFORMS[job_idx];

    assert_ne!(caps.platform, job.platform);
    assert!(
        !matches(&caps, &job),
        "platform mismatch accepted: caps={:?}, job={:?}",
        caps.platform,
        job.platform
    );
}

// ----------------------------------------------------------------------------
// Property 5 — missing required runtime never matches.
// If the job requires a runtime the runner does not offer, match is false.
// ----------------------------------------------------------------------------
#[hegel::test]
fn missing_runtime_never_matches(tc: hegel::TestCase) {
    let caps = draw_capabilities(&tc);
    let mut job = JobRequirements {
        cpu: caps.cpu,
        memory_mb: caps.memory_mb,
        platform: caps.platform,
        runtimes: caps.runtimes.clone(),
    };

    let missing: Vec<Runtime> = RUNTIMES
        .iter()
        .copied()
        .filter(|r| !caps.runtimes.contains(r))
        .collect();
    if missing.is_empty() {
        return;
    }
    let pick = tc.draw(
        generators::integers::<usize>()
            .min_value(0)
            .max_value(missing.len() - 1),
    );
    job.runtimes.insert(missing[pick]);

    assert!(
        !matches(&caps, &job),
        "missing runtime accepted: caps.runtimes={:?}, job.runtimes={:?}",
        caps.runtimes,
        job.runtimes
    );
}
