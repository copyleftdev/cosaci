---
id: github-checks-integration
source: SPEC.md §11.1
class: D
status: pending
---

# github-checks-integration

**Claim:** CosaCI publishes GitHub Check statuses that correctly reflect internal status-lifecycle transitions. PRs block on CosaCI checks; completed checks appear with the expected title, conclusion, and summary.

**Why class D:** this is an integration-test domain. GitHub's Checks API behavior, webhook delivery, and app-installation model are external and subject to their own SLAs. The Hegel layer cannot test them.

**What *can* be tested (and is, elsewhere):**
- `status-lifecycle` (class A) — the internal state machine whose transitions drive the external publish calls.
- Recorded-fixture integration tests that replay past GitHub webhook payloads through the ingestion path.
- Smoke tests against a real test GitHub org on every release candidate.

**Notes:** This card exists so the claim doesn't disappear. Validation is delegated to:
- `tests/integration/github_webhooks.rs` (recorded fixtures; out of scope for Hegel).
- A weekly routine against a real test org (can be `/schedule`d as a background agent once we stabilize).
