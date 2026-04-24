# Workspace Layout (target for v0.2)

The current `cosaci` crate is one library + four binaries. The dependency
graph supports a 5-library + 3-binary workspace split. This document is
the design we'd file as the first refactor PR.

## Goals

- **Compile-time isolation of heavy deps.** `wasmtime`, `schnorrkel`,
  and `rustls` each pull dozens of transitive crates. Consumers that
  don't need them shouldn't pay for them.
- **Reusability.** `cosaci-core` should be useful outside CosaCI as a
  library of property-tested distributed primitives.
- **Clear API surface.** Each crate has a narrow purpose; `pub` items
  are the contract, `pub(crate)` items are implementation.
- **No premature splitting.** Resist the urge to give every module its
  own crate. Three+ consumers or a heavy-dep boundary is the bar.

## Target structure

```
cosaci/                              workspace root
├── Cargo.toml                       [workspace] members + shared deps
├── SPEC.md
├── docs/
│
├── crates/
│   ├── cosaci-core/                 pure algebra + crypto primitives
│   │   └── src/                     (no I/O, no network, no heavy deps)
│   │
│   ├── cosaci-state/                stateful subsystems
│   │   └── src/                     (depends: cosaci-core)
│   │
│   ├── cosaci-protocol/             wire protocol + TLS transport
│   │   └── src/                     (depends: cosaci-core; heavy: rustls, rcgen)
│   │
│   ├── cosaci-vrf/                  VRF primitive (heavy: schnorrkel, merlin)
│   │   └── src/                     (depends: cosaci-core)
│   │
│   └── cosaci-wasm/                 WASM runtime (heavy: wasmtime)
│       └── src/                     (depends: cosaci-core)
│
└── bins/
    ├── cosaci-coordinator/          coordinator binary
    │   └── src/main.rs              (depends: state + protocol + vrf + wasm)
    │
    ├── cosaci-agent/                agent binary
    │   └── src/main.rs              (depends: state + protocol + vrf + wasm)
    │
    └── cosaci-demo/                 single-process + networked demo runner
        └── src/{bin/demo.rs, bin/demo_networked.rs}
```

## Module → crate mapping

| Current (`src/`)            | Target crate          | Notes                         |
| --------------------------- | --------------------- | ----------------------------- |
| `clock.rs`                  | core                  | trait + `SystemClock`         |
| `signing.rs`                | core                  | ed25519-dalek wrapper         |
| `attestation.rs`            | core                  | needs `signing`               |
| `quorum.rs`                 | core                  | pure aggregate                |
| `confidentiality.rs`        | core                  | AEAD                          |
| `capabilities.rs`           | core                  | match predicate               |
| `gossip.rs`                 | core                  | LWW CRDT                      |
| `bloom.rs`                  | core                  | filter                        |
| `flake.rs`                  | core                  | scoring                       |
| `reputation.rs`             | core                  | scoring                       |
| `status.rs`                 | core                  | DAG                           |
| `verifier.rs`               | core                  | Merkle verifier               |
| `merkle_log.rs`             | core                  | append log + MMR              |
| `lease.rs`                  | state                 | uses `core::clock`            |
| `registry.rs`               | state                 |                                |
| `aggregator.rs`             | state                 | uses `core::quorum`           |
| `partition.rs`              | state                 | uses `state::lease`           |
| `replicated_cluster.rs`     | state                 | uses `state::lease`           |
| `replay.rs`                 | state                 | uses `core::clock`, `core::bloom` |
| `rate_limit.rs`             | state                 | uses `core::clock`            |
| `sharding.rs`               | state                 |                                |
| `sharding_handoff.rs`       | state                 | uses `state::sharding`        |
| `proto.rs`                  | protocol              | uses `core::attestation`      |
| `tls.rs`                    | protocol              | rustls / rcgen / pemfile      |
| `vrf.rs`                    | vrf                   | schnorrkel / merlin           |
| `wasm_runtime.rs`           | wasm                  | wasmtime                      |
| `bin/coordinator.rs`        | `cosaci-coordinator`  | depends on all libs           |
| `bin/agent.rs`              | `cosaci-agent`        | depends on all libs           |
| `bin/demo*.rs`              | `cosaci-demo`         | depends on all libs           |

## Workspace `Cargo.toml` skeleton

```toml
[workspace]
resolver = "2"
members = [
    "crates/cosaci-core",
    "crates/cosaci-state",
    "crates/cosaci-protocol",
    "crates/cosaci-vrf",
    "crates/cosaci-wasm",
    "bins/cosaci-coordinator",
    "bins/cosaci-agent",
    "bins/cosaci-demo",
]

[workspace.package]
version = "0.2.0"
edition = "2024"
authors = ["copyleftdev"]
license = "MIT OR Apache-2.0"
repository = "https://github.com/copyleftdev/cosaci"

[workspace.dependencies]
# Shared deps with pinned versions across all members.
serde            = { version = "1.0", features = ["derive"] }
serde-big-array  = "0.5"
ciborium         = "0.2"
sha2             = "0.11"
ed25519-dalek    = "2.2"
chacha20poly1305 = "0.10"
rs_merkle        = "1.5"
rustls           = { version = "0.23", default-features = false, features = ["ring", "std"] }
rustls-pemfile   = "2.2"
rcgen            = "0.14"
schnorrkel       = "0.11"
merlin           = "3.0"
wasmtime         = { version = "44", default-features = false, features = ["cranelift", "wat", "runtime"] }
rand             = "0.10"
rand_chacha      = "0.10"
hegeltest        = "0.8"
criterion        = { version = "0.7", features = ["html_reports"] }
```

## Migration plan (4 PRs)

### PR 1 — Workspace skeleton (no module moves yet)
- Create `crates/` and `bins/` directories.
- Add a stub `Cargo.toml` in each future crate location, marked
  `publish = false` (won't be published to crates.io until v1).
- Wire up `[workspace]` in the top-level `Cargo.toml`.
- Confirm `cargo build` and `cargo test` still produce the same artifacts
  (the original `src/` is still the source of truth for now).
- **Done when:** `cargo metadata` shows the new workspace structure and
  the original tests still pass.

### PR 2 — Move `cosaci-core` + `cosaci-state`
- Move the algebra and stateful modules to their new crates in two
  successive commits.
- Update `cosaci` (the meta-crate) to re-export the moved types from
  `cosaci-core` and `cosaci-state` so existing tests keep compiling.
- **Done when:** all 32 test files still pass; `cargo build` of any
  bin still produces a working binary.

### PR 3 — Isolate `vrf`, `wasm`, `protocol`
- Move `vrf.rs` → `cosaci-vrf`.
- Move `wasm_runtime.rs` → `cosaci-wasm`.
- Move `proto.rs` + `tls.rs` → `cosaci-protocol`.
- Confirm: `cargo build -p cosaci-core` does NOT compile `wasmtime` or
  `schnorrkel` (the isolation works).
- **Done when:** core build is materially faster.

### PR 4 — Move bins to dedicated bin crates
- Move `src/bin/coordinator.rs` → `bins/cosaci-coordinator/src/main.rs`.
- Same for `agent` and the two demos.
- Delete the original `src/bin/` directory.
- Confirm: `cargo run -p cosaci-coordinator -- --addr 127.0.0.1:7878 ...`
  still works. `cargo run -p cosaci-demo --bin demo_networked` runs
  end-to-end.
- **Done when:** the original `cosaci` package is gone (or just the
  meta-crate) and every binary runs from its dedicated crate.

## Open questions (surfaced by the split, answered during PR review)

1. **`Attestation::sign_with` — public API or impl detail?**
   Current callers (binaries) use it. Likely public; document the
   self-excluding signature pattern.

2. **Should `tls::TestCa` move to a separate `cosaci-test-utils` crate?**
   Production won't generate test CAs. Either:
   - Keep in `cosaci-protocol` behind a `test-utils` feature.
   - Move to a new `cosaci-test-utils` dev-dep.

3. **Versioning across the workspace.**
   Bump-together until v1.0 is the simplest discipline. Breaking
   changes are minor bumps until then.

4. **`cosaci-core` as a public reusable crate.**
   When does this stabilize enough to publish to crates.io?
   Suggested: after v0.3, when API drift has settled.

5. **Where does the canned WAT live?**
   `cosaci-wasm` for now; long-term it's an example, not a primitive.

## What this split is not

- Not a rewrite. Every module stays the same; only the directory and
  `Cargo.toml` boundaries move.
- Not an API change. The four binaries should be byte-identical in
  behavior before and after.
- Not a milestone in itself. The split is enabling work for the v0.2
  hardening agenda.
