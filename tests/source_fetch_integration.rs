//! Integration test for `cosaci_jobs::source_fetch::execute_source_fetch`.
//!
//! Builds a tiny fixture repo at test time (no committed `.git`
//! directories under `tests/fixtures/`), then drives the executor
//! against it via a `file://` URL. Verifies that:
//!
//! 1. Two independent calls against the same `(url, sha)` produce
//!    equal `tree_hash` and `resolved_sha`.
//! 2. Pointing the same call at a different commit changes the
//!    `output_hash`.
//! 3. The pipeline DSL surfaces the executor through
//!    `Step::SourceFetch`.

use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::process::Command;

use cosaci::jobs::source_fetch::{execute_source_fetch, output_hash};
use cosaci::jobs::{Pipeline, Step, StepStatus, execute_pipeline};
use tempfile::tempdir;

/// Initialize a small git repo at `path` and return the commit SHAs
/// in chronological order.
fn build_fixture_repo(path: &Path) -> Vec<String> {
    fn git(args: &[&str], cwd: &Path) {
        let out = Command::new("git")
            .args(args)
            .current_dir(cwd)
            .output()
            .expect("git available");
        assert!(
            out.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
    }

    git(&["init", "-q", "-b", "main"], path);
    // A throwaway identity for the fixture commits — `git commit`
    // refuses to run without one. Configure locally so the host's
    // global config is untouched.
    git(&["config", "user.email", "fixture@cosaci.test"], path);
    git(&["config", "user.name", "Fixture Bot"], path);
    // Commits must be reproducible across runs — pin author/committer
    // dates and disable signing.
    git(&["config", "commit.gpgsign", "false"], path);

    let mut shas = Vec::new();
    for (i, content) in ["alpha\n", "beta\n", "gamma\n"].iter().enumerate() {
        let f = path.join("README.md");
        let mut h = File::create(&f).expect("create README");
        h.write_all(content.as_bytes()).expect("write README");
        git(&["add", "README.md"], path);
        // Pin the date so the SHAs are reproducible. Values are
        // arbitrary but fixed — chosen to land in 2026.
        let date = format!("2026-04-2{} 12:00:00 +0000", i);
        let env = [
            ("GIT_AUTHOR_DATE", date.as_str()),
            ("GIT_COMMITTER_DATE", date.as_str()),
        ];
        let msg = format!("commit {i}");
        let out = Command::new("git")
            .args(["commit", "-q", "-m", &msg])
            .envs(env)
            .current_dir(path)
            .output()
            .expect("git available");
        assert!(
            out.status.success(),
            "git commit failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let sha_out = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(path)
            .output()
            .expect("git available");
        assert!(sha_out.status.success());
        shas.push(String::from_utf8_lossy(&sha_out.stdout).trim().to_string());
    }
    shas
}

#[test]
fn executes_against_local_fixture_and_is_self_consistent() {
    let upstream = tempdir().expect("upstream tempdir");
    let shas = build_fixture_repo(upstream.path());
    let url = format!("file://{}", upstream.path().display());

    // Two independent executions against the same SHA must agree.
    let a = execute_source_fetch(&url, &shas[1]).expect("fetch A");
    let b = execute_source_fetch(&url, &shas[1]).expect("fetch B");
    assert_eq!(a.resolved_sha, b.resolved_sha, "resolved_sha unstable");
    assert_eq!(
        a.resolved_sha, shas[1],
        "resolved_sha != requested sha — checkout didn't land on the right commit"
    );
    assert_eq!(
        a.tree_hash, b.tree_hash,
        "tree_hash unstable across independent fetches of the same SHA"
    );

    // Different SHA → different output_hash. (The tree differs by
    // README content, so tree_hash differs too — but the property
    // we want guaranteed is the composed output_hash binding both.)
    let c = execute_source_fetch(&url, &shas[2]).expect("fetch C");
    assert_ne!(
        output_hash(&a),
        output_hash(&c),
        "different SHAs produced equal output_hash — branch-moves-mid-round undetectable"
    );

    // Cleanup happens implicitly when `upstream` drops.
    let _ = fs::metadata(upstream.path());
}

#[test]
fn pipeline_step_source_fetch_executes() {
    let upstream = tempdir().expect("upstream tempdir");
    let shas = build_fixture_repo(upstream.path());
    let url = format!("file://{}", upstream.path().display());

    let p = Pipeline {
        steps: vec![Step::SourceFetch {
            url,
            reference: shas[0].clone(),
        }],
    };
    let r = execute_pipeline(&p).expect("execute pipeline");
    assert_eq!(r.steps.len(), 1);
    assert!(
        matches!(r.steps[0].status, StepStatus::Success),
        "SourceFetch step didn't succeed: status={:?}",
        r.steps[0].status
    );
}
