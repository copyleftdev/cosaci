---
id: webhook-auth-gate
source: SPEC.md §13.2
class: A
status: passing
test: tests/webhook_auth_gate.rs
depends_on:
  - submission-auth-gate
introduced_by: issue/52
---

# Webhook auth gate

The webhook listener (#52) is the bridge between SCM events
(GitHub / GitLab) and the per-tenant signed submission path
(#46). Two algebra-level gates apply *before* an event becomes
a `JobSubmission`:

1. **Provider signature verification.** GitHub: HMAC-SHA-256
   of the raw body, header `X-Hub-Signature-256: sha256=…`.
   GitLab: shared-secret token in the `X-Gitlab-Token` header,
   constant-time-compared. A failure at this step is a
   reject — the listener never reaches the job-submission path.
2. **Freshness window.** The event's timestamp must be within
   `window_secs` of `now`. Replays of bit-equal valid webhooks
   are otherwise undetectable; the freshness check is what
   makes them rejectable.

## Falsifiable claims

For any `(body, secret, header_value, event_ts, now)`:

- **Honest signing accepts** — when `header_value` is built by
  computing HMAC-SHA-256 of `body` with `secret` and
  hex-encoding the result with the `sha256=` prefix,
  `verify_github_signature` returns `Ok(())`.
- **Wrong secret rejects** — verifying under a different
  `secret` produces `BadSignature`.
- **Tampered body rejects** — flipping any bit of `body` after
  signing produces `BadSignature`.
- **Malformed header rejects** — header values without the
  `sha256=` prefix, with non-hex characters, or with the
  wrong length produce `Malformed` (a distinct verdict so
  operator dashboards can distinguish "client bug" from
  "active attack").
- **Constant-time comparison** — both `verify_github_signature`
  and `verify_gitlab_token` finish in time independent of
  *where* the comparison fails. Encoded informally via
  `hmac::Mac::verify_slice` (which is documented to be
  constant-time) and a hand-rolled constant-time eq for the
  GitLab token path.
- **Freshness window** — `is_fresh(event_ts, now, w)` is
  `true` iff `|event_ts - now| <= w`. Boundary checked at
  exactly `w` and `w + 1`.

## Why this is class A

Each property is a pointwise statement over a single function
call. Hegel can falsify with a single counterexample; the
shrinker can isolate the minimum bit-flip in `body` or the
minimum offset in `event_ts`.

## .cosaci.toml round-trip

The manifest parser ships alongside the signature gate. The
property `parse(emit(m)) == m` (over Hegel-drawn manifests)
is the standard serialization-stability check; documented in
the same hypothesis card so the round-trip claim doesn't
fragment across files.

## Out of scope (follow-on)

- **HTTP listener bin.** This card encodes the *property*; the
  axum/hyper server that exposes `POST /webhook/github` and
  `POST /webhook/gitlab` is plumbing on top.
- **`.cosaci.toml` → `Pipeline` translation.** The manifest
  parses cleanly here, but the listener's job of resolving
  `{{ event.* }}` templates and constructing a signed
  `JobSubmission` is the follow-on.
- **Live-fixture integration test against real GitHub /
  GitLab webhook bodies recorded into `tests/fixtures/`**.
  The current test uses synthetic bodies; recorded fixtures
  are the issue's acceptance criterion #5 and lands with
  the listener bin.
