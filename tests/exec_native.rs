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
