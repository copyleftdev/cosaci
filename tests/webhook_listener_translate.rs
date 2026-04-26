//! Fixture-replay integration test for
//! `cosaci_webhook::translate`.
//!
//! Pairs synthetic-but-realistic GitHub / GitLab webhook event
//! bodies (under `tests/fixtures/webhook/`) with hand-written
//! `.cosaci.toml` manifests, drives the translation, and
//! asserts the resolved pipeline matches the expected shape.
//! Closes the recorded-fixture acceptance criterion of #52
//! at the algebra layer; the HTTP listener bin's end-to-end
//! is exercised by build + smoke-test only (the listener is a
//! thin wrapper over the translate primitive).

use cosaci::webhook::{ResolvedStep, parse_manifest, translate};

fn load_fixture(name: &str) -> serde_json::Value {
    let path = format!("tests/fixtures/webhook/{name}");
    let text = std::fs::read_to_string(&path).expect(&path);
    serde_json::from_str(&text).expect("fixture JSON")
}

#[test]
fn github_pr_synchronize_resolves_url_and_head_sha() {
    let manifest = parse_manifest(
        r#"
[tenant]
id = 1

[[pipeline]]
name = "ci"
on   = ["pull_request.synchronize"]

  [[pipeline.step]]
  type      = "source-fetch"
  url       = "{{ event.repository.clone_url }}"
  reference = "{{ event.pull_request.head.sha }}"
"#,
    )
    .expect("parse manifest");

    let event = load_fixture("github_pull_request_synchronize.json");
    let resolved = translate(&manifest, "pull_request.synchronize", &event).expect("translate");

    assert_eq!(resolved.len(), 1, "exactly one matching pipeline");
    assert_eq!(resolved[0].name, "ci");
    assert_eq!(resolved[0].steps.len(), 1);
    match &resolved[0].steps[0] {
        ResolvedStep::SourceFetch { url, reference } => {
            assert_eq!(url, "https://github.com/example-org/widget-svc.git");
            assert_eq!(reference, "9f1e2c3a4b5d6e7f8091a2b3c4d5e6f7a8b9c0d1");
        }
        other @ ResolvedStep::ExecWasm { .. } => {
            panic!("expected SourceFetch, got {other:?}")
        }
    }
}

#[test]
fn gitlab_push_resolves_clone_url_and_sha() {
    let manifest = parse_manifest(
        r#"
[tenant]
id = 7

[[pipeline]]
name = "ci"
on   = ["Push Hook.push"]

  [[pipeline.step]]
  type      = "source-fetch"
  url       = "{{ event.project.git_http_url }}"
  reference = "{{ event.checkout_sha }}"
"#,
    )
    .expect("parse manifest");

    let event = load_fixture("gitlab_push.json");
    // GitLab's listener composes "<X-Gitlab-Event>.<object_kind>" via
    // `compose_event_name`; the fixture has `object_kind: "push"` and
    // a synthetic header `Push Hook` so the composed name is
    // "Push Hook.push".
    let resolved = translate(&manifest, "Push Hook.push", &event).expect("translate");

    assert_eq!(resolved.len(), 1);
    match &resolved[0].steps[0] {
        ResolvedStep::SourceFetch { url, reference } => {
            assert_eq!(
                url,
                "https://gitlab.example.test/example-org/widget-svc.git"
            );
            assert_eq!(reference, "abcdef0011223344556677889900aabbccddeeff");
        }
        other @ ResolvedStep::ExecWasm { .. } => {
            panic!("expected SourceFetch, got {other:?}")
        }
    }
}

#[test]
fn pipeline_with_non_matching_event_returns_no_resolutions() {
    let manifest = parse_manifest(
        r#"
[tenant]
id = 1

[[pipeline]]
name = "ci"
on   = ["pull_request.opened"]

  [[pipeline.step]]
  type      = "source-fetch"
  url       = "https://example.test/repo.git"
  reference = "main"
"#,
    )
    .expect("parse manifest");

    let event = load_fixture("github_pull_request_synchronize.json");
    let resolved = translate(&manifest, "pull_request.synchronize", &event).expect("translate");
    assert!(resolved.is_empty(), "non-matching event must not trigger");
}

#[test]
fn unresolved_placeholder_is_an_error() {
    let manifest = parse_manifest(
        r#"
[tenant]
id = 1

[[pipeline]]
name = "ci"
on   = ["pull_request.synchronize"]

  [[pipeline.step]]
  type      = "source-fetch"
  url       = "{{ event.no.such.field }}"
  reference = "main"
"#,
    )
    .expect("parse manifest");

    let event = load_fixture("github_pull_request_synchronize.json");
    let err = translate(&manifest, "pull_request.synchronize", &event).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("unresolved") || msg.contains("no.such.field"),
        "unexpected error: {msg}"
    );
}

#[test]
fn unsupported_namespace_is_an_error() {
    let manifest = parse_manifest(
        r#"
[tenant]
id = 1

[[pipeline]]
name = "ci"
on   = ["pull_request.synchronize"]

  [[pipeline.step]]
  type      = "source-fetch"
  url       = "{{ env.SECRET }}"
  reference = "main"
"#,
    )
    .expect("parse manifest");

    let event = load_fixture("github_pull_request_synchronize.json");
    let err = translate(&manifest, "pull_request.synchronize", &event).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("unsupported") || msg.contains("env"),
        "unexpected error: {msg}"
    );
}

#[test]
fn placeholder_in_exec_wasm_field_is_rejected() {
    let manifest = parse_manifest(
        r#"
[tenant]
id = 1

[[pipeline]]
name = "ci"
on   = ["push"]

  [[pipeline.step]]
  type        = "exec-wasm"
  module_path = "{{ event.repository.clone_url }}"
  args_cbor_hex = "8200"
"#,
    )
    .expect("parse manifest");

    let event = load_fixture("github_pull_request_synchronize.json");
    let err = translate(&manifest, "push", &event).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("literal-only field") || msg.contains("module_path"),
        "unexpected error: {msg}"
    );
}

#[test]
fn multiple_pipelines_match_independently() {
    let manifest = parse_manifest(
        r#"
[tenant]
id = 1

[[pipeline]]
name = "fast"
on   = ["pull_request.synchronize"]

  [[pipeline.step]]
  type      = "source-fetch"
  url       = "{{ event.repository.clone_url }}"
  reference = "{{ event.pull_request.head.sha }}"

[[pipeline]]
name = "slow"
on   = ["pull_request.synchronize", "push"]

  [[pipeline.step]]
  type      = "source-fetch"
  url       = "{{ event.repository.clone_url }}"
  reference = "{{ event.pull_request.head.sha }}"
"#,
    )
    .expect("parse manifest");

    let event = load_fixture("github_pull_request_synchronize.json");
    let resolved = translate(&manifest, "pull_request.synchronize", &event).expect("translate");

    assert_eq!(resolved.len(), 2);
    assert_eq!(resolved[0].name, "fast");
    assert_eq!(resolved[1].name, "slow");
}
