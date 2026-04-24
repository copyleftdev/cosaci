# CosaCI Roadmap

Milestones map directly to GitHub milestones and group the initial
issues a fresh repo would file. See `docs/REPO_BOOTSTRAP.md` for the
`gh` commands that create them.

## v0.2.0 — Workspace + Hardening

Goal: split into a Cargo workspace, close audit gates, finish protocol
hardening, ship a documentation pass.

### Workspace split (4 issues)
Tracks `docs/WORKSPACE_LAYOUT.md` exactly.

- **#1 — Workspace skeleton (no module moves yet).** kind/refactor,
  area/build, priority/P1.
- **#2 — Move `cosaci-core` + `cosaci-state`.** kind/refactor,
  area/core area/state, priority/P1, blocked by #1.
- **#3 — Isolate `vrf`, `wasm`, `protocol`.** kind/refactor, area/vrf
  area/wasm area/protocol, priority/P1, blocked by #2.
- **#4 — Move bins to dedicated bin crates.** kind/refactor, area/bin,
  priority/P1, blocked by #3.

### Protocol hardening (4 issues)

- **#5 — Persistent coordinator (loop instead of one-shot).** Listen
  forever; accept multiple jobs; clean per-job state; graceful
  shutdown. kind/feat, area/coordinator, priority/P1.
- **#6 — Real WASM payloads in `Assign` envelopes.** Carry a `.wasm`
  blob + serialized inputs; current canned WAT becomes an example.
  kind/feat, area/protocol area/wasm, priority/P1.
- **#7 — VRF-proof committee verification.** Agents submit `VRFProof`
  with `Register`; coordinator verifies via
  `cosaci::vrf::verify` before counting them.
  kind/feat, area/vrf area/coordinator, priority/P1.
- **#8 — Cert rotation + revocation hooks.** Closes the deferred
  half of `mtls-enforcement`. kind/feat, area/protocol, priority/P2.

### Audit gates (4 issues)

- **#9 — `cargo clippy --all-targets -- -D clippy::pedantic` clean.**
  Fix or `#[allow]`-annotate every pedantic finding. kind/chore,
  area/build, priority/P1.
- **#10 — `cargo deny check` integrated.** Add `deny.toml` with
  license + advisory + sources policy. kind/chore, area/build,
  priority/P1.
- **#11 — `cargo fmt --check` enforced.** Add `.rustfmt.toml`.
  kind/chore, area/build, priority/P2.
- **#12 — Doc coverage: `#![deny(missing_docs)]` on every public
  item.** kind/docs, area/core area/state, priority/P2.

### CI + release (3 issues)

- **#13 — GitHub Actions CI workflow.** Run `cargo test --workspace`,
  the bench compile, and the audit gates on every PR. kind/chore,
  area/ci, priority/P1.
- **#14 — `CHANGELOG.md` + semver discipline.** Document the bump
  policy: bump-together until v1.0; minor for breaking changes;
  patch for non-breaking fixes. kind/docs, area/release, priority/P2.
- **#15 — Crate metadata + initial release prep.** Fill in
  `[package.description]`, `keywords`, `categories`, `readme`. Block
  `crates.io` publish behind a `publish = false` until v1.0; the bins
  ship via GitHub releases as static binaries. kind/chore,
  area/release, priority/P2.

## v0.3.0 — Production-ready binaries

Goal: take the demo wire-up to a usable system someone could run
against a small fleet.

### Real-world workflow (4 issues)

- **#16 — Job submission CLI on the coordinator.** Accept jobs from
  stdin / a small REST or socket endpoint instead of one-shot.
  kind/feat, area/coordinator, priority/P1.
- **#17 — Persistent attestation log on disk.** `cosaci-core` Merkle
  log gets a `Store` trait; default impl writes append-only to a
  file with periodic Merkle-root checkpoint. kind/feat, area/state
  area/coordinator, priority/P2.
- **#18 — Agent capability advertisement.** `Register` envelope
  carries `Capabilities`; coordinator filters committee selection
  by capability match. kind/feat, area/protocol area/coordinator,
  priority/P2.
- **#19 — Slashing on detected dishonest attestation.** When quorum
  finds a signature mismatch with majority result, the offending
  runner's stake decrements; persist this state. kind/feat,
  area/state, priority/P2.

### Test coverage gaps (3 issues)

- **#20 — `real-partition-recovery` C-class via netem (gated).** Run
  inside a Linux network namespace; only run under
  `HEGEL_NET_HARNESS=1`. kind/test, area/state, priority/P3.
- **#21 — `tee-attestation` C-class via swtpm (gated).** Run only
  under `HEGEL_TEE_HARNESS=1` with `swtpm` available. kind/test,
  area/protocol, priority/P3.
- **#22 — `github-checks-integration` D-class via recorded
  fixtures.** Implement the GitHub-publishing code path in
  `cosaci-coordinator` first; then the test mocks against recorded
  webhook payloads. kind/feat kind/test, area/coordinator,
  priority/P3.

## v1.0.0 — Public beta

Goal: the spec is stable enough to publish, the system is operable in
a small production setting, and at least one external consumer is
running it.

To-be-detailed when v0.3 lands. Likely shape:
- Cross-org federation (multiple coordinators trust-bridging via the
  same Merkle anchor bulletin).
- Public crates.io publish for `cosaci-core`.
- Documented operator runbook.
- Security audit pass.

## Issue label taxonomy

```
kind/{bug, feat, refactor, chore, docs, test, perf}
priority/{P0, P1, P2, P3}
area/{core, state, protocol, vrf, wasm, coordinator, agent, demo, ci, build, release, bin}
status/{blocked, in-progress, needs-review}
good first issue
help wanted
flaky
```

Rationale:
- **`kind/*`** — what the change is (one per issue).
- **`priority/*`** — when it should ship (one per issue; P0 = blocker).
- **`area/*`** — which crate / subsystem (multiple allowed).
- **`status/*`** — workflow signal (multiple allowed transiently).
- The bottom three are conventional.
