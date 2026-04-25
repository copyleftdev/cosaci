# Changelog

All notable changes to CosaCI are documented in this file. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Until v1.0.0, all crates in the (eventual) workspace bump together;
breaking changes are minor bumps; non-breaking changes are patch
bumps. v1.0 onward, each crate versions independently.

## [Unreleased]

In-progress v0.2.0 work, accumulating since the v0.1.0 tag. Each
section below corresponds to a merged PR; the version isn't tagged
until the v0.2 milestone closes (see `docs/ROADMAP.md`).

### Added — workspace + crate boundaries (#1, #2, #3, #4)

- 5-library + 3-binary Cargo workspace. `cosaci-core` (algebra +
  crypto primitives), `cosaci-state` (lifecycle: leases, registry,
  aggregator, partition, replicated cluster, replay, rate limit,
  sharding, sharding-handoff), `cosaci-protocol` (CBOR envelope +
  rustls mTLS + rcgen test CA + CRL helpers), `cosaci-vrf`
  (schnorrkel sr25519), `cosaci-wasm` (wasmtime).
- Bins live under `bins/cosaci-{coordinator,agent,demo}` with
  short `[[bin]]` names (`coordinator`, `agent`, `demo`,
  `demo_networked`).
- Heavy deps (`wasmtime`, `schnorrkel`, `rustls`, `rcgen`) only
  pulled by the crates that actually need them — verified via
  `cargo tree -p cosaci-core`.
- Meta-crate is a thin re-export shim that keeps the existing 32
  integration tests + benches compiling against `cosaci::*` paths.

### Added — persistent coordinator + SIGTERM drain (#5)

- Coordinator is no longer one-shot: after the fleet registers,
  it enters a job loop, reuses agent connections across jobs,
  and only exits on `--max-jobs` or SIGINT/SIGTERM.
- `signal-hook`-driven drain flag checked at every iteration
  boundary: in-flight job finishes, loop exits, agents get a
  Shutdown envelope, exit code 0. Verified end-to-end in
  `demo_networked`'s two-pass run.

### Added — real WASM payloads in Assign (#6)

- `Envelope::Assign` carries `module: Vec<u8>` (binary `.wasm`)
  and `args_cbor: Vec<u8>` instead of `(a, b)`. Wire ABI v0.2
  documented in `cosaci-wasm`: modules export
  `add(i32, i32) -> i32`; args decode from CBOR `(i32, i32)`.
- `output_hash(module_hash, result)` binds the output to the
  module that produced it, so two committee members executing
  different modules can never quorum on the same artifact.
- `MAX_ENVELOPE_BYTES` raised 1 MiB → 16 MiB to fit real modules.
- New Hegel property: `different_modules_disambiguate_outputs`
  encodes the module-hash binding as a falsifiable claim.

### Added — VRF-proof committee verification (#7)

- Replaces the SHA-256(vrf_pk || seed) pseudo-VRF committee
  selection with real verifiable VRFs. `Register` now carries a
  proof of possession over a fixed challenge string; the
  coordinator runs a per-job VRF round (`JobSeed` → `VrfClaim`)
  and verifies every proof before picking the committee as
  top-k by lexicographically smallest VRF output.
- New `Envelope::JobSeed` and `Envelope::VrfClaim` variants.

### Added — cert rotation + CRL hooks (#8)

- `cosaci-protocol::tls`: `read_crls`,
  `server_config_from_paths_with_crl`, `server_config_with_crls`,
  `TestCa::issue_crl`. CRL plumbing is verified by two new
  Hegel properties: `revoked_client_cert_is_rejected` and
  `non_revoked_client_cert_succeeds_with_crl`.
- Coordinator `--crl <path>` flag + SIGHUP-triggered hot reload
  of the cert/key/CRL bundle. Existing TLS connections survive
  the swap by design; only new handshakes pick up the new config.

### Changed — code quality + audit gates (#9, #10, #11, #12, #13)

- Workspace-wide `clippy::pedantic` gate via
  `[workspace.lints.clippy]`. Each blanket allow has a
  justification comment in `Cargo.toml`.
- `deny.toml` curated with allow-listed licenses (MIT,
  Apache-2.0, BSD-2/3-Clause, ISC, Zlib, 0BSD, MPL-2.0,
  Unicode-3.0/DFS-2016, CDLA-Permissive-2.0); two RUSTSEC IDs
  ignored with rationale (paste, rustls-pemfile unmaintained).
  CI's `cargo deny check` flipped from advisory
  (`continue-on-error: true`) to a real gate.
- `.rustfmt.toml` makes the implicit fmt policy explicit
  (edition 2024, max_width 100, stable-only options).
- Every public item across the five lib crates carries a
  docstring; `#![deny(missing_docs)]` enforces this at build
  time, not just CI.
- `rust-toolchain.toml` pins Rust 1.94.0 + rustfmt + clippy.
  Local builds and CI run against identical compiler versions;
  no MSRV creep when a new stable lands.

### Changed — protocol envelope shapes

The wire protocol is **not** stable across v0.1 → v0.2.
`Envelope::Assign` and `Envelope::Register` both gained fields
this cycle (module bytes / VRF proofs); this is a clean break,
no compatibility shim. The cosaci crates are `publish = false`
so this only matters to in-tree callers.

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
