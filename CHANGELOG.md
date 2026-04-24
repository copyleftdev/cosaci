# Changelog

All notable changes to CosaCI are documented in this file. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Until v1.0.0, all crates in the (eventual) workspace bump together;
breaking changes are minor bumps; non-breaking changes are patch
bumps. v1.0 onward, each crate versions independently.

## [Unreleased]

Nothing yet.

## [0.1.0] — 2026-04-24

The initial release. Library of property-tested distributed
primitives + a working mTLS-secured coordinator/agent demo.

### Added — falsifiable spec + audit trail

- `SPEC.md` — 17-section spec at public-infrastructure scale.
- `hypotheses/` — 33 hypothesis cards + index.md audit trail.
  Every spec claim is mapped to a card, tagged class A / B-stat / C / D,
  and either has a passing Hegel test or a documented `blocked_on:` note.

### Added — primitives (`src/`)

- **Cryptography:** Ed25519 signing wrapper with strict verification
  (`signing`); ChaCha20-Poly1305 envelope encryption (`confidentiality`);
  schnorrkel sr25519 VRF with merlin transcript binding (`vrf`);
  rustls + rcgen + PEM I/O mTLS harness (`tls`).
- **Attestation:** canonical CBOR + SHA-256 (`attestation`); Merkle
  verifier with inclusion-proof soundness (`verifier`); append-only
  Merkle log with MMR peak decomposition (`merkle_log`); bloom
  filter for scale variant of the replay window (`bloom`).
- **Lifecycle:** stake-weighted quorum aggregator (`quorum`);
  Pending/Pass/Fail/Escalate result lifecycle with max-retries
  (`aggregator`); per-(job, runner) lease manager with TTL
  (`lease`); SCM status DAG (`status`); replay protection by
  nonce + Clock window (`replay`); per-tenant token-bucket rate
  limiter (`rate_limit`).
- **Distribution:** runner registry (`registry`); capability
  matching (`capabilities`); single-state-with-gate cluster
  (`partition`); two-replica cluster with split-brain +
  reset-to-majority reconciliation (`replicated_cluster`); LWW
  CRDT for gossip (`gossip`); atomic sharded store (`sharding`);
  phased-handoff sharded store (`sharding_handoff`).
- **Scoring:** flake confidence (`flake`); reputation
  monotonicity (`reputation`).
- **Time + execution:** injectable `Clock` trait + `SystemClock`
  (`clock`); WASM execution via wasmtime (`wasm_runtime`).
- **Wire:** CBOR `Envelope` + length-prefixed framing (`proto`).

### Added — binaries

- `cargo run --bin demo` — single-process end-to-end pipeline.
- `cargo run --bin coordinator` — mTLS-listening coordinator.
- `cargo run --bin agent` — mTLS-connecting agent.
- `cargo run --bin demo_networked` — spawns coordinator + 5 agents
  as separate processes with a fresh CA + per-process certs.

### Added — testing + benchmarks

- 32 integration test files under `tests/`; ~100 Hegel properties
  total. All green at HEAD.
- `benches/hot_paths.rs` — criterion baselines on quorum aggregate,
  attestation canonicalize + hash, Ed25519 sign + verify, VRF
  evaluate + verify, Merkle verifier, gossip merge.
- 3 Hegel shrinks caught and resolved during development:
  `vrf-assignment-uniformity` (distinctness precondition),
  `sybil-resistance` (honest-noise vs. adversary-coordination
  modeling), `bloom-fp-rate` (saturation regime outside formula's
  domain of validity).

### Added — design + repo bootstrap docs

- `README.md` — quickstart + how-to-read-this-repo guide.
- `CHANGELOG.md` — this file.
- `docs/ARCHITECTURE.md` — layered model, trust chain, dep graph.
- `docs/WORKSPACE_LAYOUT.md` — target 5-lib/3-bin Cargo workspace
  + 4-PR migration plan.
- `docs/ROADMAP.md` — v0.2 / v0.3 / v1.0 milestones, 22 initial
  issues across the first two milestones.
- `docs/REPO_BOOTSTRAP.md` — `gh` commands to bootstrap a private
  repo at `copyleftdev/cosaci` with labels, milestones, and the
  initial v0.2 issue set.
- `.github/labels.yml` — 30 labels (kind / priority / area /
  status / conventional) in `github-label-sync` format.
- `.github/ISSUE_TEMPLATE/{bug,feature,refactor,config}.yml` —
  GitHub issue forms; bug template asks for the shrunk Hegel
  counterexample, feature template asks for SPEC.md sections
  affected, refactor template asks for blast radius +
  verification plan.
- `.github/PULL_REQUEST_TEMPLATE.md` — checklist enforces
  test/lint/fmt/deny gates and asks about hypothesis cards
  affected.
- `.github/workflows/ci.yml` — GitHub Actions CI workflow.

### Architecture decisions captured in this release

- **Per-(job, runner) lease keying** — the architectural finding
  surfaced by integration testing: a quorum-based CI assigns
  K-runner committees per job; each `(job, runner)` pair gets its
  own lease. The single-job-keyed model from earlier was wrong.
- **Six locked primitives** for public-infrastructure scale:
  sharded small-Raft groups + gossip; pubkey + stake-weighted
  quorum; VRF assignment; local append-only log + periodic
  Merkle-root anchoring; WASM-primary sandbox with Firecracker
  escalation; stake + slashing economics (payment deferred to v2).

### Known limitations of v0.1

- The coordinator is **one-shot** — it serves a single job and
  exits. Persistent loop is `v0.2.0` issue #5.
- The `Assign` envelope carries `(a, b)` for a canned WAT module.
  Real WASM payloads are `v0.2.0` issue #6.
- Committee selection uses `SHA-256(vrf_pk || seed)` lex-min
  rather than full VRF-proof verification by the coordinator.
  v0.2 issue #7.
- mTLS does not yet support cert rotation or CRL/OCSP revocation.
  v0.2 issue #8.

[Unreleased]: https://github.com/copyleftdev/cosaci/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/copyleftdev/cosaci/releases/tag/v0.1.0
