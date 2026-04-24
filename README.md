# CosaCI

> **A distributed, attested CI execution mesh.** Property-tested at every layer.

CosaCI replaces a single CI runner with a quorum of stake-weighted runners that
each execute the same job in a sandbox, sign their results, and converge on a
Merkle-anchored attestation. Trust is layered: mTLS for the connection,
Ed25519 for the attestation, stake-weighted quorum for agreement, Merkle log
for provenance.

This repository is the foundational library + a working end-to-end demo.

## Status

```
33 hypothesis cards · 30 passing · ~100 Hegel properties green
3 Hegel shrinks caught and resolved during development
6 source commits + 1 design commit on main
0 deferred sub-claims at the algebraic / state-machine layer
```

The 3 remaining cards are externally blocked: real netem/Jepsen partitions,
TPM/SGX/SEV TEE attestation, and the GitHub-publishing code path that
doesn't exist yet (it's a v0.3 deliverable).

## Quickstart

```bash
# Run the full property-test suite (~10s).
cargo test

# Single-process end-to-end demo: VRF assignment → WASM execution →
# signed attestation → stake-weighted quorum → Merkle anchor.
cargo run --bin demo

# Networked end-to-end demo: spawns a coordinator + 5 agents as
# separate processes, all talking over mTLS with a fresh CA + per-
# process certificates generated at startup.
cargo run --bin demo_networked

# Hot-path benchmarks.
cargo bench --bench hot_paths
```

The networked demo prints something like:

```
[launcher] CA + certs in /tmp/cosaci-demo-NNNNN
[coord]    listening on 127.0.0.1:7879 (mTLS)
[agentN]   connecting / registered (mTLS ✓)
[coord]    fleet assembled (5 agents)
[coord]    committee: [2, 0, 1]
[agentN]   assigned job 1: add(21, 21) → attestation submitted
[coord]    runner N attestation sig=ok artifact=[…]
[coord]    quorum outcome Pass (threshold 200, committee stake 300)
[coord]    anchored at position 0 root […]
```

## How to read this repo

| File / dir              | What it is                                                  |
| ----------------------- | ----------------------------------------------------------- |
| `SPEC.md`               | The falsifiable specification (17 sections, public-infra scale). |
| `hypotheses/index.md`   | Audit table — every spec claim mapped to a card and a test. |
| `hypotheses/<id>.md`    | One claim per card with class A / B-stat / C / D and status. |
| `tests/`                | One Rust file per card; ~100 Hegel property tests in total. |
| `src/`                  | 26 narrow-purpose modules; no module imports something below it that isn't strictly needed. |
| `src/bin/`              | `coordinator`, `agent`, `demo`, `demo_networked`.           |
| `benches/hot_paths.rs`  | Criterion baselines on the trust-chain hot paths.           |
| `docs/ARCHITECTURE.md`  | Layered model, trust chain, dep graph, primitive choices.   |
| `docs/WORKSPACE_LAYOUT.md` | The v0.2 cargo workspace plan (5 libs + 3 bins).          |
| `docs/ROADMAP.md`       | v0.2 / v0.3 / v1.0 milestones and initial issue list.       |
| `docs/REPO_BOOTSTRAP.md`| `gh` commands to bootstrap labels / milestones / issues.    |

## Method

The development discipline is **spec-as-falsifiable-artifact**. The
`SPEC.md` document is treated as a falsifiable research artifact. Each
claim becomes a Hegel property test under `tests/`. `cargo test` is the
act of filtering: a green test corroborates the claim, a shrunk
counterexample is a successful falsification (the filter found
something), and `blocked_on:` notes are honest non-coverage. No claim
silently disappears. Three real Hegel shrinks have been resolved this
way, captured in card frontmatter.

## v0.1 → v0.2

This repo is v0.1. The library is one Rust crate; v0.2 splits into a
Cargo workspace (5 libs + 3 bins) per `docs/WORKSPACE_LAYOUT.md`. The
v0.2 issue list is in `docs/ROADMAP.md` and ready to file in one
copy-paste from `docs/REPO_BOOTSTRAP.md`.

## License

Dual-licensed under either of:

- Apache License, Version 2.0 (`LICENSE-APACHE`)
- MIT license (`LICENSE-MIT`)

at your option.
