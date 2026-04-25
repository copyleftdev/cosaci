//! Fixture-replay tests for the GitHub Checks API publishing
//! contract.
//!
//! Encodes the falsifiable claim of
//! `hypotheses/github-checks-integration.md` (issue #38, class D).
//! The card is "boundary" — GitHub's API is external — but the
//! **payload contract** is testable here: given a CosaCI status
//! lifecycle state + job context, the generated `CheckRunPayload`
//! conforms to the documented schema.
//!
//! These tests serialize the payload via `serde_json` and compare
//! the result to a captured fixture. A change that breaks the
//! schema (renamed field, missing required key, wrong serialization
//! tag) breaks the fixture comparison at PR time without needing
//! a live GitHub API call.
//!
//! Fixtures live under `tests/fixtures/github_checks/`. Keep them
//! pretty-printed with stable key order (serde defaults; we don't
//! re-sort) so a diff is human-readable on regression.

use cosaci::github_checks::{
    CheckConclusion, CheckRunPayload, CheckStatus, JobContext, build_payload,
    status_to_check_status,
};
use cosaci::status::Status;

const COMMIT_SHA: &str = "abcdef0123456789abcdef0123456789abcdef01";
const JOB_NAME: &str = "cosaci/build";
const DETAILS_URL: &str = "https://coord.example/jobs/42";
const OUTPUT_TITLE: &str = "CosaCI · Job 42";

fn ctx(summary: &str) -> JobContext<'_> {
    JobContext {
        name: JOB_NAME,
        commit_sha: COMMIT_SHA,
        details_url: Some(DETAILS_URL),
        summary,
        title: OUTPUT_TITLE,
    }
}

/// Read a fixture and parse it into a `CheckRunPayload`. Failure
/// here means the fixture is malformed — fix the JSON, not the
/// production code.
fn load_fixture(name: &str) -> CheckRunPayload {
    let path = format!("tests/fixtures/github_checks/{name}.json");
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read fixture {path}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse fixture {path}: {e}"))
}

// ────────────────────────────────────────────────────────────────────────
// Lifecycle → CheckStatus mapping (Property 1).
// ────────────────────────────────────────────────────────────────────────
#[test]
fn pending_maps_to_queued() {
    let (s, c) = status_to_check_status(Status::Pending);
    assert_eq!(s, CheckStatus::Queued);
    assert_eq!(c, None);
}

#[test]
fn running_maps_to_in_progress() {
    let (s, c) = status_to_check_status(Status::Running);
    assert_eq!(s, CheckStatus::InProgress);
    assert_eq!(c, None);
}

#[test]
fn quorum_verifying_maps_to_in_progress() {
    let (s, c) = status_to_check_status(Status::QuorumVerifying);
    assert_eq!(s, CheckStatus::InProgress);
    assert_eq!(c, None);
}

#[test]
fn success_maps_to_completed_with_success_conclusion() {
    let (s, c) = status_to_check_status(Status::Success);
    assert_eq!(s, CheckStatus::Completed);
    assert_eq!(c, Some(CheckConclusion::Success));
}

#[test]
fn failure_maps_to_completed_with_failure_conclusion() {
    let (s, c) = status_to_check_status(Status::Failure);
    assert_eq!(s, CheckStatus::Completed);
    assert_eq!(c, Some(CheckConclusion::Failure));
}

// ────────────────────────────────────────────────────────────────────────
// Payload contract: each lifecycle state matches its fixture.
// ────────────────────────────────────────────────────────────────────────
#[test]
fn pending_matches_fixture() {
    let summary = "Job accepted; awaiting committee selection.";
    let actual = build_payload(Status::Pending, &ctx(summary));
    let expected = load_fixture("pending");
    assert_eq!(actual, expected);
}

#[test]
fn running_matches_fixture() {
    let summary = "Committee dispatched (3 runners). Pipeline executing.";
    let actual = build_payload(Status::Running, &ctx(summary));
    let expected = load_fixture("running");
    assert_eq!(actual, expected);
}

#[test]
fn quorum_verifying_matches_fixture() {
    let summary = "Committee finished; aggregating attestations against 2/3-weighted quorum.";
    let actual = build_payload(Status::QuorumVerifying, &ctx(summary));
    let expected = load_fixture("quorum_verifying");
    assert_eq!(actual, expected);
}

#[test]
fn success_matches_fixture() {
    let summary = "Pass quorum reached. Anchored at log position 137; root b1c2d3e4…";
    let actual = build_payload(Status::Success, &ctx(summary));
    let expected = load_fixture("success");
    assert_eq!(actual, expected);
}

#[test]
fn failure_matches_fixture() {
    let summary = "Fail quorum reached. Committee voted 2/3 fail; minority slashed.";
    let actual = build_payload(Status::Failure, &ctx(summary));
    let expected = load_fixture("failure");
    assert_eq!(actual, expected);
}

// ────────────────────────────────────────────────────────────────────────
// Schema contract: serialized JSON has the keys GitHub expects.
// ────────────────────────────────────────────────────────────────────────
#[test]
fn schema_completed_payload_has_conclusion_field() {
    let payload = build_payload(Status::Success, &ctx("ok"));
    let json = serde_json::to_value(&payload).expect("serialize");
    assert_eq!(json["status"], "completed");
    assert_eq!(json["conclusion"], "success");
    assert!(json.get("name").is_some(), "name field present");
    assert!(json.get("head_sha").is_some(), "head_sha field present");
    assert!(json.get("output").is_some(), "output field present");
    assert!(json["output"].get("title").is_some());
    assert!(json["output"].get("summary").is_some());
}

#[test]
fn schema_running_payload_omits_conclusion_field() {
    let payload = build_payload(Status::Running, &ctx("ok"));
    let json = serde_json::to_value(&payload).expect("serialize");
    assert_eq!(json["status"], "in_progress");
    assert!(
        json.get("conclusion").is_none(),
        "conclusion must be absent for non-Completed statuses; \
         GitHub rejects payloads where conclusion is set without status=completed"
    );
}

#[test]
fn schema_details_url_optional() {
    let mut c = ctx("no-url");
    c.details_url = None;
    let payload = build_payload(Status::Pending, &c);
    let json = serde_json::to_value(&payload).expect("serialize");
    assert!(
        json.get("details_url").is_none(),
        "details_url must be absent (not null) when caller omits it"
    );
}

// ────────────────────────────────────────────────────────────────────────
// Smoke — round-trip through serde_json.
// ────────────────────────────────────────────────────────────────────────
#[test]
fn smoke_round_trip_through_json() {
    for s in [
        Status::Pending,
        Status::Running,
        Status::QuorumVerifying,
        Status::Success,
        Status::Failure,
    ] {
        let payload = build_payload(s, &ctx("round-trip test"));
        let json = serde_json::to_string(&payload).expect("serialize");
        let parsed: CheckRunPayload = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(payload, parsed);
    }
}
