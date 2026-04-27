//! Integration tests for `cosaci_jobs::Step::ExecNative` (issue #107
//! PR 1 of N — plain executor, no sandbox yet).
//!
//! Tests are gated `#[cfg(unix)]` because the canned commands
//! (`/bin/echo`, `/bin/sh -c 'exit 7'`, `sleep`) are POSIX-shaped.
//! macOS + Linux both pass.
//!
//! What this verifies:
//!
//! 1. **Basic exec** — `/bin/echo` returns `Success` with bounded
//!    stdout that round-trips deterministically across runs.
//! 2. **Non-zero exit** — `/bin/sh -c 'exit 7'` returns `Failed`
//!    and the exit code is bound into the `output_hash`.
//! 3. **Spawn failure** — a missing executable returns `Failed`
//!    deterministically (same `output_hash` across runs for the
//!    same kind of failure).
//! 4. **Wall-time enforcement** — `sleep 5` with `wall_seconds=1`
//!    returns `LimitExceeded { Wall }` within ~1s.
//! 5. **Stdout determinism** — running the same command twice
//!    yields identical step `output_hash` and identical
//!    `final_artifact_hash`.
//! 6. **Distinct stdout → distinct hash** — different `echo`
//!    arguments produce distinct `output_hash`es; the executor
//!    can't accidentally collapse different observations into
//!    the same canonical bytes.

#![cfg(unix)]

use std::collections::BTreeMap;
use std::time::Instant;

use cosaci::jobs::{Limits, Pipeline, Step, StepStatus, execute_pipeline};

fn echo_pipeline(args: &[&str]) -> Pipeline {
    let mut argv: Vec<String> = vec!["/bin/echo".into()];
    argv.extend(args.iter().map(|s| (*s).to_string()));
    Pipeline {
        steps: vec![Step::ExecNative {
            command: argv,
            env: BTreeMap::new(),
            limits: Limits::default(),
        }],
    }
}

#[test]
fn echo_runs_to_success() {
    let p = echo_pipeline(&["hello"]);
    let r = execute_pipeline(&p).expect("execute");
    assert!(
        matches!(r.steps[0].status, StepStatus::Success),
        "expected Success, got {:?}",
        r.steps[0].status
    );
}

#[test]
fn nonzero_exit_is_failed() {
    let p = Pipeline {
        steps: vec![Step::ExecNative {
            command: vec!["/bin/sh".into(), "-c".into(), "exit 7".into()],
            env: BTreeMap::new(),
            limits: Limits::default(),
        }],
    };
    let r = execute_pipeline(&p).expect("execute");
    assert!(
        matches!(r.steps[0].status, StepStatus::Failed),
        "expected Failed, got {:?}",
        r.steps[0].status
    );
}

#[test]
fn missing_executable_is_failed_deterministically() {
    // Two runs with the same (non-existent) command must produce
    // byte-equal results. The "spawn failed" hash binds the
    // io::ErrorKind so different failure modes (NotFound vs
    // PermissionDenied) hash differently — but identical NotFound
    // failures across runs hash equally.
    let p = Pipeline {
        steps: vec![Step::ExecNative {
            command: vec!["/this/path/does/not/exist/cosaci-test".into()],
            env: BTreeMap::new(),
            limits: Limits::default(),
        }],
    };
    let r1 = execute_pipeline(&p).expect("run 1");
    let r2 = execute_pipeline(&p).expect("run 2");
    assert!(matches!(r1.steps[0].status, StepStatus::Failed));
    assert_eq!(
        r1, r2,
        "spawn-failure runs diverged; output_hash must be deterministic"
    );
}

#[test]
fn wall_timeout_kills_long_running_child() {
    let p = Pipeline {
        steps: vec![Step::ExecNative {
            command: vec!["/bin/sh".into(), "-c".into(), "sleep 5".into()],
            env: BTreeMap::new(),
            limits: Limits {
                wall_seconds: 1,
                ..Limits::default()
            },
        }],
    };
    let start = Instant::now();
    let r = execute_pipeline(&p).expect("execute");
    let elapsed = start.elapsed();

    // Should be killed at ~1s, not run for the full 5s. Allow
    // slack for the 50ms watchdog poll interval and process
    // teardown — but it MUST be well under 5s.
    assert!(
        elapsed.as_secs() < 4,
        "wall timeout didn't kill the child in time: {elapsed:?}"
    );
    use cosaci::jobs::LimitKind;
    assert!(
        matches!(
            r.steps[0].status,
            StepStatus::LimitExceeded {
                which: LimitKind::Wall
            }
        ),
        "expected LimitExceeded {{ Wall }}, got {:?}",
        r.steps[0].status
    );
}

#[test]
fn same_command_same_hash() {
    let p = echo_pipeline(&["determinism"]);
    let r1 = execute_pipeline(&p).expect("run 1");
    let r2 = execute_pipeline(&p).expect("run 2");
    assert_eq!(r1, r2, "same ExecNative diverged across runs");
}

#[test]
fn different_args_distinct_hash() {
    let r_a = execute_pipeline(&echo_pipeline(&["alpha"])).expect("alpha");
    let r_b = execute_pipeline(&echo_pipeline(&["beta"])).expect("beta");
    assert_ne!(
        r_a.final_artifact_hash, r_b.final_artifact_hash,
        "distinct stdout collapsed into the same final_artifact_hash"
    );
    assert_ne!(
        r_a.steps[0].output_hash, r_b.steps[0].output_hash,
        "distinct stdout collapsed into the same step output_hash"
    );
}

#[test]
fn empty_command_is_failed_deterministically() {
    let p = Pipeline {
        steps: vec![Step::ExecNative {
            command: vec![],
            env: BTreeMap::new(),
            limits: Limits::default(),
        }],
    };
    let r1 = execute_pipeline(&p).expect("run 1");
    let r2 = execute_pipeline(&p).expect("run 2");
    assert!(matches!(r1.steps[0].status, StepStatus::Failed));
    assert_eq!(r1, r2, "empty-command runs diverged");
}

// ────────────────────────────────────────────────────────────────────────
// cgroup-v2 memory enforcement (#107 PR 2 of N).
//
// These tests are gated on the host having cgroup-v2 + user
// delegation of the memory controller. On a host that lacks
// either (e.g. cgroup-v1, no systemd, no user@.service scope),
// the per-step cgroup setup returns None and memory_mb is a
// no-op. To keep the test honest in either environment, we
// detect the capability up-front and skip with a clear stdout
// note rather than producing false-positive `Success` verdicts.
// ────────────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn cgroup_v2_memory_delegated() -> bool {
    // Mirror the production helpers without exposing them
    // publicly. If `/proc/self/cgroup` resolves to a v2 path
    // and that path's `cgroup.subtree_control` enables
    // `memory`, we assume the test can create a sub-cgroup.
    let Ok(text) = std::fs::read_to_string("/proc/self/cgroup") else {
        return false;
    };
    let mut path = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("0::") {
            path =
                Some(std::path::PathBuf::from("/sys/fs/cgroup").join(rest.trim_start_matches('/')));
            break;
        }
    }
    let Some(path) = path else {
        return false;
    };
    let Ok(controllers) = std::fs::read_to_string(path.join("cgroup.subtree_control")) else {
        return false;
    };
    controllers.split_whitespace().any(|c| c == "memory")
}

#[cfg(not(target_os = "linux"))]
fn cgroup_v2_memory_delegated() -> bool {
    false
}

#[test]
fn memory_oom_kill_attributed_to_limit_kind() {
    if !cgroup_v2_memory_delegated() {
        eprintln!(
            "[skip] memory_oom_kill_attributed_to_limit_kind: cgroup-v2 memory controller not delegated on this host"
        );
        return;
    }
    // Allocate ~256 MiB in a single shell process while the
    // cgroup memory cap is 16 MiB. The kernel's cgroup OOM
    // killer fires, the cgroup records `oom_kill > 0`, and
    // the executor attributes the failure to
    // LimitExceeded { Memory } rather than a generic Failed.
    //
    // The allocator: `head -c 256M /dev/zero` reads 256 MiB
    // from /dev/zero and writes it to stdout. We pipe that
    // into `cat` (which reads incrementally). Without a
    // memory cap this completes in ms; with a 16 MiB cap, the
    // cgroup OOM-kill fires when buffered bytes pile up.
    //
    // Wrap it in a /dev/null sink so the parent pipe doesn't
    // become the limiter.
    let p = Pipeline {
        steps: vec![Step::ExecNative {
            command: vec![
                "/bin/sh".into(),
                "-c".into(),
                // tail -c 256M reads the whole 256 MiB into
                // a single allocation before writing — perfect
                // for blowing past a 16 MiB cgroup cap.
                "tail -c 268435456 /dev/zero >/dev/null".into(),
            ],
            env: BTreeMap::new(),
            limits: Limits {
                memory_mb: 16,
                wall_seconds: 30,
                ..Limits::default()
            },
        }],
    };
    use cosaci::jobs::LimitKind;
    let r = execute_pipeline(&p).expect("execute");
    assert!(
        matches!(
            r.steps[0].status,
            StepStatus::LimitExceeded {
                which: LimitKind::Memory
            }
        ),
        "expected LimitExceeded {{ Memory }}, got {:?}",
        r.steps[0].status
    );
}

#[test]
fn memory_within_budget_succeeds() {
    if !cgroup_v2_memory_delegated() {
        eprintln!(
            "[skip] memory_within_budget_succeeds: cgroup-v2 memory controller not delegated on this host"
        );
        return;
    }
    // /bin/echo allocates ~tens of KB. A 64 MiB cap is
    // generous; the step should run cleanly and report Success.
    // This is the negative control for the OOM test — confirms
    // the cgroup setup itself doesn't break unrelated steps.
    let p = Pipeline {
        steps: vec![Step::ExecNative {
            command: vec!["/bin/echo".into(), "within-budget".into()],
            env: BTreeMap::new(),
            limits: Limits {
                memory_mb: 64,
                ..Limits::default()
            },
        }],
    };
    let r = execute_pipeline(&p).expect("execute");
    assert!(
        matches!(r.steps[0].status, StepStatus::Success),
        "expected Success, got {:?}",
        r.steps[0].status
    );
}

// ────────────────────────────────────────────────────────────────────────
// cgroup-v2 cpu enforcement (#107 PR 3 of N).
//
// cgroup-v2's cpu.max is a rate limiter (bandwidth, not
// cumulative time), so total-CPU-time enforcement is done by
// polling cpu.stat::usage_usec every WALL_POLL_INTERVAL and
// killing the child when it exceeds cpu_seconds. Tests gated on
// cgroup-v2 cpu controller delegation.
// ────────────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn cgroup_v2_cpu_delegated() -> bool {
    let Ok(text) = std::fs::read_to_string("/proc/self/cgroup") else {
        return false;
    };
    let mut path = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("0::") {
            path =
                Some(std::path::PathBuf::from("/sys/fs/cgroup").join(rest.trim_start_matches('/')));
            break;
        }
    }
    let Some(path) = path else {
        return false;
    };
    let Ok(controllers) = std::fs::read_to_string(path.join("cgroup.subtree_control")) else {
        return false;
    };
    controllers.split_whitespace().any(|c| c == "cpu")
}

#[cfg(not(target_os = "linux"))]
fn cgroup_v2_cpu_delegated() -> bool {
    false
}

#[test]
fn cpu_limit_kills_busy_loop() {
    if !cgroup_v2_cpu_delegated() {
        eprintln!(
            "[skip] cpu_limit_kills_busy_loop: cgroup-v2 cpu controller not delegated on this host"
        );
        return;
    }
    // A busy-wait shell loop pegs one core. With
    // cpu_seconds=1, the executor's poll loop should detect
    // cpu.stat::usage_usec >= 1_000_000 within one
    // WALL_POLL_INTERVAL (50 ms) and kill the child — well
    // before the 30s wall_seconds backstop fires.
    //
    // Wall_seconds is set to a generous backstop so a
    // regression that breaks cpu enforcement gets caught here
    // (LimitExceeded { Wall }) rather than hanging the test
    // suite for minutes.
    let p = Pipeline {
        steps: vec![Step::ExecNative {
            command: vec!["/bin/sh".into(), "-c".into(), "while :; do :; done".into()],
            env: BTreeMap::new(),
            limits: Limits {
                cpu_seconds: 1,
                wall_seconds: 30,
                ..Limits::default()
            },
        }],
    };
    use cosaci::jobs::LimitKind;
    let start = Instant::now();
    let r = execute_pipeline(&p).expect("execute");
    let elapsed = start.elapsed();

    // Should be killed in ~1-2s, well under wall_seconds.
    assert!(
        elapsed.as_secs() < 5,
        "cpu limit didn't kill the child in time: {elapsed:?}"
    );
    assert!(
        matches!(
            r.steps[0].status,
            StepStatus::LimitExceeded {
                which: LimitKind::Cpu
            }
        ),
        "expected LimitExceeded {{ Cpu }}, got {:?}",
        r.steps[0].status
    );
}

#[test]
fn cpu_within_budget_succeeds() {
    if !cgroup_v2_cpu_delegated() {
        eprintln!("[skip] cpu_within_budget_succeeds: cgroup-v2 cpu controller not delegated");
        return;
    }
    // /bin/echo uses ~milliseconds of CPU. cpu_seconds=10 is
    // generous; the step should run cleanly. Negative control
    // for the busy-loop test — confirms cpu enforcement
    // doesn't break unrelated steps.
    let p = Pipeline {
        steps: vec![Step::ExecNative {
            command: vec!["/bin/echo".into(), "cpu-within-budget".into()],
            env: BTreeMap::new(),
            limits: Limits {
                cpu_seconds: 10,
                ..Limits::default()
            },
        }],
    };
    let r = execute_pipeline(&p).expect("execute");
    assert!(
        matches!(r.steps[0].status, StepStatus::Success),
        "expected Success, got {:?}",
        r.steps[0].status
    );
}

#[test]
fn memory_limit_zero_is_no_enforcement() {
    // memory_mb: 0 = unlimited (matching wall_seconds: 0
    // semantics). The cgroup is NOT created; the step runs
    // exactly as PR 1 did. Allocates 64 MiB, well under the
    // host's free memory, succeeds.
    let p = Pipeline {
        steps: vec![Step::ExecNative {
            command: vec![
                "/bin/sh".into(),
                "-c".into(),
                "head -c 67108864 /dev/zero >/dev/null".into(),
            ],
            env: BTreeMap::new(),
            limits: Limits {
                memory_mb: 0,
                wall_seconds: 30,
                ..Limits::default()
            },
        }],
    };
    let r = execute_pipeline(&p).expect("execute");
    assert!(
        matches!(r.steps[0].status, StepStatus::Success),
        "expected Success with no enforcement, got {:?}",
        r.steps[0].status
    );
}
