---
id: github-checks-integration
source: SPEC.md §11.1
class: D
status: passing
test: tests/github_checks_fixtures.rs
---

# github-checks-integration

**Claim:** CosaCI publishes GitHub Check statuses that correctly
reflect internal status-lifecycle transitions. PRs block on CosaCI
checks; completed checks appear with the expected title,
conclusion, and summary.

## Why class D

This is an integration-test domain. GitHub's Checks API behavior,
webhook delivery, and app-installation model are external state
the Hegel layer can't test directly.

## What's testable at the contract layer (and now is)

The card moves from `pending` to `passing` via fixture replay
(issue #38). `cosaci-state::github_checks` exposes:

- `CheckRunPayload` struct matching GitHub's documented schema for
  `POST /repos/{owner}/{repo}/check-runs`.
- `status_to_check_status(Status) -> (CheckStatus, Option<CheckConclusion>)` —
  pure mapping from CosaCI's `cosaci-core::status::Status` lifecycle
  to GitHub's `(status, conclusion)` pair.
- `build_payload(Status, &JobContext) -> CheckRunPayload` — full
  payload assembly.

The fixture-replay test in `tests/github_checks_fixtures.rs`
captures one canonical JSON for each lifecycle state under
`tests/fixtures/github_checks/{pending,running,quorum_verifying,success,failure}.json`.
Any change to `build_payload` that breaks the schema (renamed
field, missing required key, wrong serialization tag) fails the
fixture comparison at PR time.

## Statement (testable here)

For every value of `cosaci_core::status::Status`:

1. **Status mapping.** `status_to_check_status` produces:
   - `Pending` → `(Queued, None)`
   - `Running` → `(InProgress, None)`
   - `QuorumVerifying` → `(InProgress, None)`
   - `Success` → `(Completed, Some(Success))`
   - `Failure` → `(Completed, Some(Failure))`

2. **Schema conformance.** The serialized JSON:
   - Always has `name`, `head_sha`, `status`, `output.title`,
     `output.summary`.
   - Has `conclusion` IFF `status == Completed`. (GitHub rejects
     payloads with `conclusion` set when `status != completed`.)
   - Has `details_url` IFF the caller provided one (no null
     fields).

3. **Fixture round-trip.** For each canonical
   `(Status, JobContext)` pair, the generated payload equals the
   captured fixture.

## Class

**D** (boundary). The Hegel layer can't observe what GitHub
actually does with the payload — that requires a live API token
and a test repo. What it CAN observe is whether our payload
matches the documented contract; the fixture comparison nails
that down.

## Falsification candidates

- Renaming a field on `CheckRunPayload` (e.g. `head_sha` →
  `commit_sha`) — fixture comparison fails for every state.
- Forgetting `#[serde(skip_serializing_if = "Option::is_none")]`
  on `conclusion` — Property 2 catches it (a `running` payload
  emits `conclusion: null` and GitHub rejects).
- Changing `CheckStatus` serialization (e.g. dropping
  `rename_all = "snake_case"` so `InProgress` serializes as
  `"InProgress"` instead of `"in_progress"`) — every fixture
  fails.

## What's NOT covered (live-API integration)

The class C / live-API tests are out of scope:
- Posting to a real test org against a GitHub App token.
- Webhook ingestion (issue #52).
- Coordinator-side "publish on every status transition" plumbing
  (issue #38's first acceptance bullet — the live HTTP path).

These remain as `/schedule`-able weekly routines once a test
GitHub org is provisioned.

## Coverage

5 lifecycle-mapping unit tests + 5 fixture-replay tests + 3
schema-shape tests + 1 round-trip smoke = **14 total** in
`tests/github_checks_fixtures.rs`.
