//! GitHub Checks API publishing — pure payload transformation.
//!
//! Source: `SPEC.md` §11.1 / `hypotheses/github-checks-integration.md`
//! (class D). The card is "boundary": GitHub's Checks API behavior,
//! webhook delivery, and app-installation model are external state
//! that the Hegel layer can't test directly. What it **can** test is
//! the **payload contract**: given a CosaCI `Status` (from the
//! `cosaci-core::status` lifecycle, class A) plus job context, the
//! generated `CheckRunPayload` conforms to GitHub's documented
//! schema for `POST /repos/{owner}/{repo}/check-runs`.
//!
//! Fixture-replay tests under `tests/github_checks_fixtures.rs`
//! anchor that contract: any change to the transformation that
//! breaks the documented schema gets caught at PR time without
//! needing a live GitHub API call.
//!
//! # What's NOT in this module
//!
//! - HTTP client / actual API calls. The runner / coord composes
//!   the payload here and hands it to whatever HTTP layer it has
//!   access to. The "publish on every status transition" plumbing
//!   in the coordinator lands in a follow-on PR (the issue's first
//!   acceptance bullet).
//! - GitHub App authentication (JWT minting, installation tokens).
//!   Out of scope until the live publish path is wired.
//! - Webhook payload **ingestion**. CosaCI doesn't yet receive
//!   webhooks (issue #52). When that lands, the inverse contract
//!   gets its own card.

use serde::{Deserialize, Serialize};

use cosaci_core::status::Status;

/// What CosaCI POSTs to `https://api.github.com/repos/{owner}/{repo}/check-runs`.
///
/// Field shapes match GitHub's documented schema as of 2026-04. The
/// fixture tests in `tests/github_checks_fixtures.rs` lock the
/// serialization down; a divergence from the schema breaks the
/// fixture comparison at PR time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckRunPayload {
    /// Display name of the check run. Operators set this in their
    /// CosaCI deployment config; typical value is the
    /// project / pipeline name.
    pub name: String,
    /// SHA of the commit the check applies to. 40 lowercase hex
    /// chars (Git's standard).
    pub head_sha: String,
    /// Lifecycle state at GitHub. Mapped from CosaCI's `Status`
    /// per [`status_to_check_status`].
    pub status: CheckStatus,
    /// Required when `status == Completed`; absent otherwise. Maps
    /// from CosaCI's terminal `Status::Success` / `Status::Failure`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conclusion: Option<CheckConclusion>,
    /// Public URL for the run details. CosaCI deployments typically
    /// point this at the read-API job-bundle endpoint (issue #44)
    /// so the auditor can pull the Merkle proof.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details_url: Option<String>,
    /// Human-readable summary block.
    pub output: CheckOutput,
}

/// GitHub's `status` enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    /// Accepted but not started.
    Queued,
    /// Currently running.
    InProgress,
    /// Terminal — see `conclusion` for the result class.
    Completed,
}

/// GitHub's `conclusion` enum (only valid when `status == Completed`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckConclusion {
    /// Quorum agreed Pass.
    Success,
    /// Quorum agreed Fail.
    Failure,
    /// Reserved — used when CosaCI returns `Outcome::Escalate`
    /// (no consensus reached). Operators interpret this as
    /// "needs review", not as pass or fail.
    Neutral,
    /// Job was canceled (e.g. SIGTERM during the run).
    Cancelled,
    /// Reserved for future use; not currently emitted by CosaCI.
    Skipped,
}

/// The visible-on-GitHub block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckOutput {
    /// Short header — typically `"CosaCI · Job <id>"`.
    pub title: String,
    /// Markdown summary visible in the GitHub UI. Typical content:
    /// quorum threshold, committee runner_ids, attestation count,
    /// Merkle log root + position, link to the read-API bundle.
    pub summary: String,
}

/// Job context the caller supplies to the payload builder. Lifted
/// out of the coordinator so the transformation itself stays pure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobContext<'a> {
    /// Display name for the check run (e.g. `"cosaci/build"`).
    pub name: &'a str,
    /// 40-char lowercase commit SHA.
    pub commit_sha: &'a str,
    /// Optional URL to the run details (read-API bundle).
    pub details_url: Option<&'a str>,
    /// Markdown-rendered summary content.
    pub summary: &'a str,
    /// `Output.title`. Caller decides; convention is
    /// `"CosaCI · Job {id}"`.
    pub title: &'a str,
}

/// Map a CosaCI `Status` to GitHub's `(check_status, conclusion)`
/// pair. Pure: same input always produces same output.
#[must_use]
pub fn status_to_check_status(s: Status) -> (CheckStatus, Option<CheckConclusion>) {
    // GitHub doesn't model "verifying quorum" — both Running and
    // QuorumVerifying surface as `in_progress`. The summary block
    // is what disambiguates them in the operator's UI.
    match s {
        Status::Pending => (CheckStatus::Queued, None),
        Status::Running | Status::QuorumVerifying => (CheckStatus::InProgress, None),
        Status::Success => (CheckStatus::Completed, Some(CheckConclusion::Success)),
        Status::Failure => (CheckStatus::Completed, Some(CheckConclusion::Failure)),
    }
}

/// Build a `CheckRunPayload` for the given status + context. The
/// caller is responsible for delivering the resulting JSON to
/// GitHub's API.
#[must_use]
pub fn build_payload(status: Status, ctx: &JobContext<'_>) -> CheckRunPayload {
    let (check_status, conclusion) = status_to_check_status(status);
    CheckRunPayload {
        name: ctx.name.to_string(),
        head_sha: ctx.commit_sha.to_string(),
        status: check_status,
        conclusion,
        details_url: ctx.details_url.map(str::to_string),
        output: CheckOutput {
            title: ctx.title.to_string(),
            summary: ctx.summary.to_string(),
        },
    }
}
