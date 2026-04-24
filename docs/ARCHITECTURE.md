# CosaCI Architecture (v0.1)

A snapshot of how the pieces fit together as of commit `da4a81c`. Companion to
`SPEC.md` (the falsifiable specification) and `hypotheses/index.md` (the
property-test audit trail).

## Layered model

```
┌────────────────────────────────────────────────────────────────────┐
│ Bin: src/bin/{coordinator, agent, demo, demo_networked}.rs         │
├────────────────────────────────────────────────────────────────────┤
│ Wire protocol: src/proto.rs (CBOR Envelope + length-prefix frames) │
│ Transport:     src/tls.rs   (rustls + rcgen + PEM I/O)             │
├────────────────────────────────────────────────────────────────────┤
│ Stateful subsystems                                                │
│   lease, registry, aggregator,                                     │
│   partition, replicated_cluster,                                   │
│   replay, rate_limit,                                              │
│   sharding, sharding_handoff                                       │
├────────────────────────────────────────────────────────────────────┤
│ Pure algebra + crypto primitives                                   │
│   clock (trait), signing, attestation, quorum,                     │
│   confidentiality, capabilities, gossip,                           │
│   verifier, merkle_log, bloom,                                     │
│   flake, reputation, status,                                       │
│   vrf, wasm_runtime                                                │
└────────────────────────────────────────────────────────────────────┘
```

Reading top-down: every layer depends only on the layers below it. Pure
primitives have no dependencies on stateful subsystems. The wire protocol
references types from algebra/state but does not reach into transport;
TLS sits beside wire format, not above it.

## Trust chain

```
TLS handshake (rustls + mTLS, both directions verified)
   │
   ▼
Ed25519 attestation signatures (separate per-agent keypair)
   │
   ▼
Stake-weighted quorum (cosaci::quorum::aggregate)
   │
   ▼
Merkle-anchored provenance (cosaci::merkle_log)
```

A bad actor needs to compromise all four layers to forge a passing CI
result. Each layer is independently testable; the property-test suite
covers all of them.

## Six locked primitives

| Primitive                    | Choice (v0.1)                                       |
| ---------------------------- | --------------------------------------------------- |
| Coordinator topology         | sharded small-Raft groups + cross-shard gossip      |
| Identity / quorum weighting  | pubkey + stake-weighted (slash-only economics)      |
| Assignment randomness        | VRF (schnorrkel sr25519)                            |
| Attestation log backend      | local append-only + periodic Merkle-root anchoring  |
| Sandbox default              | WASM/WASI primary; Firecracker escalation           |
| Economics                    | stake + slashing minimal; payment v2+               |

Cards in `hypotheses/` reference these as `P1`–`P6` in `depends_on`.

## Dependency graph (current single-crate)

```
clock ──────────────────────────────────┬──── lease ─────┬── partition
                                        │                ├── replicated_cluster
                                        ├──── replay     │
                                        └──── rate_limit │
                                                         │
quorum ──────────────────── aggregator ──────────────────┘

signing ──── attestation (with serde + sha2 + ciborium)

verifier ─── merkle_log (with rs_merkle MMR peaks)

vrf (schnorrkel + merlin) ── independent

confidentiality (chacha20poly1305) ── independent

bloom ── replay (sub-claim primitive)

gossip ── independent CRDT

capabilities, flake, reputation, status, registry — pure types

wasm_runtime (wasmtime) ── independent runtime

proto ── attestation (Envelope carries it)
tls ─── signing (no direct dep; rustls handles its own crypto)
```

The graph is acyclic, with three obvious heavy-dep cones (`vrf`,
`wasm_runtime`, `tls`) ready to be isolated to their own crates in v0.2.

## Three Hegel shrinks captured

The filter found three real test-design issues during development. All
three were over-strong claims — the implementation was correct, the
test was specifying more than the spec actually claims:

1. **`vrf-assignment-uniformity`** — implicit distinctness precondition
   on draws; fixed with `.unique(true)`.
2. **`sybil-resistance`** — honest-noise path could trip the "no PASS"
   assertion without any adversary action; fixed by moving randomness
   to the attacker-coordination side.
3. **`bloom-fp-rate`** — asymptotic FP-rate formula assumes
   under-saturation; fixed by floored `m_bits` and a runtime skip on
   `theoretical > 0.5`.

Each shrink narrowed the claim's domain of validity to match the spec.
This is the filter doing its job.

## Test surface

```
33 cards · 30 passing
  20 A-class:        all green (pure algebra + state machines)
   6 B-stat-class:   all green (statistical with inner sampling)
   4 C-class:        2 green (mTLS, WASM); 2 blocked (real partition,
                              TEE — external infra)
   3 D-class:        2 green (latency, meta); 1 pending (github-checks)

32 test files, ~100 Hegel properties green at HEAD.
```

Test runtime budget: ~10s for the full suite at default Hegel test counts;
~50s when slow B-stat cards are turned up to default-100 cases.

## What's NOT here

These belong to v0.2 or beyond:

- **Production coordinator:** v0.1 coordinator is one-shot. v0.2 will
  loop accept/assign cycles and persist state across restarts.
- **Real WASM payloads:** v0.1 uses a canned WAT module. v0.2 carries
  the WASM blob in `Assign` envelopes.
- **VRF-proof committee verification:** v0.1 uses
  `SHA256(vrf_pk || seed)` lex-min; agents would submit `VRFProof`
  with their `Register` and the coordinator would verify.
- **Cargo workspace split:** see `docs/WORKSPACE_LAYOUT.md`.
- **CI / cargo-deny / pedantic clippy:** see `docs/ROADMAP.md`.

## File map

```
SPEC.md                  Falsifiable spec, 17 sections
CLAUDE.md                Symlink to ../rust-claude/CLAUDE.md (overlay)
settings.json            Symlink to ../rust-claude/settings.json
Cargo.toml               Workspace member root (single crate today)
hypotheses/              33 cards + index.md (audit trail)
src/                     Library + bins (today)
src/bin/                 coordinator, agent, demo, demo_networked
tests/                   32 integration test files
benches/hot_paths.rs     criterion baselines
docs/                    This document set
.github/                 Label + template definitions for the repo
```
