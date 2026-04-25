# CosaCI

> **CI you can prove ran honestly — on machines you already own.** A
> distributed, attested execution mesh for builds and tests, designed to
> run on the laptops and workstations sitting idle in your office instead
> of paying for hosted CI minutes.

Every modern software supply chain comes down to one fragile sentence:
*"the CI says it passed."* If that CI is one rented runner, and that runner
is compromised, misconfigured, or quietly non-deterministic, every consumer
downstream is trusting a single point of failure they can't see — and
they're paying someone else by the build-minute for the privilege.

CosaCI replaces that rented runner with a **committee** of machines you
already have. Idle developer laptops. Workstations on the office network.
A retired build server in the closet. Each one runs the job in a sandbox,
signs what it observed, and the coordinator checks the committee agreed
before anchoring the result to an append-only Merkle log. A runner whose
claim disagrees with the majority loses reputation; repeated dishonesty
drops it out of the committee pool entirely.

The output isn't a green checkmark in a vendor's web UI. It's a signed,
content-addressed, independently-verifiable proof that *this commit*
produced *this artifact* under *this set of attesting runners* — replayable
locally, without trusting the CI provider, because there isn't one.

## Why this matters to you

**You're a platform / DevOps / SRE engineer** who's been quietly worried
that your CI is one compromised runner away from shipping malicious code
to production — the SolarWinds, Codecov, and event-stream story is the
same story every time. You've added attestation, SLSA, signed releases —
all of which assume the CI itself is honest. CosaCI is the layer that
stops assuming.

**You're a small team paying meaningful money each month for hosted CI
minutes** that finish in 90 seconds and then sit idle. Your fleet of dev
laptops and a build box in the corner could absorb that load ten times
over. CosaCI lets you wire those machines into a verifiable runner pool
— the trust story improves *and* the cloud bill goes down. There is no
CI vendor in the diagram.

**You're a security engineer** writing the threat model for a regulated
deploy (FedRAMP, SOC 2, PCI). Today you tell the auditor "we trust our
CI vendor." With CosaCI you hand them a Merkle proof and tell them
"verify it" — and the runners are on hardware you control, not a shared
fleet of cloud VMs you can't inspect.

**You maintain an open-source project** that gets pulled by tens of
thousands of downstream builds. A compromised release tarball is everyone's
problem. With CosaCI's attestations published alongside each release, any
consumer can verify the artifact was produced by the public, attested,
quorum-agreed pipeline — not by a one-off runner you spun up Tuesday.

**You're a research group, university, or any org with a lot of capable
hardware sitting at 5% utilization** — workstations, GPU boxes, lab
machines. Existing CI billing models force you to ignore that hardware
and rent identical capacity from a cloud. CosaCI flips it: those
machines become the runners. Quorum of three workgroup laptops + the
office build box is a perfectly good committee.

**You're a maintainer of internal CI for a multi-team org** where teams
don't fully trust each other's runner pools. Federated CosaCI gives each
team independently-verifiable evidence about every other team's builds.

## What you actually get

- **No CI vendor.** Coordinator runs on a box you control; runners are
  any machines you can put a binary on — laptops, workstations, that
  retired Mac mini, a Raspberry Pi cluster. mTLS handles auth between
  them. Per-minute billing isn't part of the model.
- **A committee, not a runner.** Each job runs on K runners (configurable;
  3 is fine for most fleets). VRF picks the committee per job — an
  attacker can't bribe "the right runner" because they can't predict
  which runners that is until the job arrives.
- **Signed attestations.** Each runner signs a statement covering the
  commit, the environment, and the output hash. Ed25519, canonical CBOR,
  no ambiguity about what was claimed.
- **Weighted quorum.** Each runner carries a reputation weight; agreement
  is by weighted vote, not raw headcount. A noisy minority can't tip
  outcomes; a high-reputation runner can't unilaterally decide them either.
- **Tamper-evident log.** Every passing build appends a leaf to a Merkle
  log. The log root is publishable; inclusion proofs are O(log n).
- **Reputation cost for misbehavior.** A runner whose attestation
  disagrees with the quorum loses reputation weight; repeated dishonesty
  drops it out of the committee pool. Bad behavior is *visible*, not just
  unsuccessful.
- **Mutual TLS everywhere.** Coordinator and agents authenticate at
  connect time; CRLs are supported and certs hot-rotate on SIGHUP.
- **WASM-first sandbox.** Jobs run as WebAssembly modules — deterministic
  execution, no host filesystem leak, no escape via shared FDs.

## A concrete day-in-the-life

Your CI submits a build job. Inside CosaCI:

1. **Coordinator** broadcasts the job seed to every registered runner.
2. **Each runner** computes a VRF over the seed, returns the output + a
   proof. The coordinator verifies every proof.
3. **Top-K** by VRF output becomes the committee. The committee is fresh
   per job and unpredictable in advance.
4. **Each committee member** receives the WASM module + arguments,
   executes it in its sandbox, hashes the output, signs a complete
   attestation.
5. **Coordinator** collects K attestations, checks they all match,
   computes the reputation-weighted quorum, and anchors the consensus
   artifact to the Merkle log.
6. **You** get a Merkle proof: "commit `abc123` produced artifact
   `def456`, attested by these public keys, anchored at log position N."
7. **An auditor**, with no access to your CI infrastructure, takes the
   public Merkle root + the proof + the attesting public keys and
   verifies the whole story locally.

That's the system. The same primitives compose into release pipelines,
deploy gates, multi-org federation, and reproducibility-sensitive build
chains.

## Try it

```bash
# Single-process end-to-end demo. Walks every primitive in one process:
# VRF assignment → WASM execution → signed attestation → weighted
# quorum → Merkle anchor.
cargo run -p cosaci-demo --bin demo

# Networked end-to-end demo. Spawns a coordinator + 5 agents as separate
# processes. Generates a fresh CA + per-process certificates at startup;
# all traffic is mTLS. Runs two passes: a bounded 3-job run, then an
# unbounded run that gets SIGTERMed mid-flight to demonstrate graceful
# drain.
cargo run -p cosaci-demo --bin demo_networked
```

The networked demo prints a running ledger of registrations, VRF rounds,
committee selections, attestations, quorum outcomes, and Merkle anchors —
roughly 50 jobs/second on a developer laptop with 5 agents.

## Project status

**v0.2** is what's in `main` today. The system runs end-to-end over real
TCP + mTLS with VRF-proof committee selection and arbitrary WASM payloads.
The 5-library + 3-binary cargo workspace is settled. CI gates on
clippy-pedantic, missing-docs, fmt, deny, and a live smoke test.

**v0.3** is scoped (see `docs/ROADMAP.md`):
- Real job submission interface (stdin → socket → optional REST).
- Persistent attestation log on disk.
- Capability-aware committee selection.
- Slashing on detected dishonest attestations.
- Three gated infrastructure-side test harnesses (netem, swtpm, recorded
  GitHub fixtures).

**v1.0** is when the spec is stable, the operator runbook exists, and at
least one external consumer is running it.

## Under the hood

The library is built on five focused crates:

- **`cosaci-core`** — pure algebra: signing, attestation canonicalization,
  Merkle log, quorum aggregation, status DAG, gossip CRDT, bloom filter.
- **`cosaci-state`** — stateful subsystems: leases, registry, partitioned
  cluster, sharded store, replay window, rate limiter.
- **`cosaci-protocol`** — wire protocol (CBOR envelopes) and mTLS
  transport (rustls + rcgen + CRL support).
- **`cosaci-vrf`** — schnorrkel sr25519 VRF.
- **`cosaci-wasm`** — wasmtime-backed sandbox harness.

Three binaries: `coordinator`, `agent`, and the `demo` runners.

## Method

CosaCI's spec is treated as a *falsifiable research artifact*. Every
externally-observable claim — committee selection is uniform under
honest distribution, mTLS rejects revoked client certs, the aggregator
forces escalation when retries exhaust, and so on — has a paired
hypothesis card under `hypotheses/` and a property test under `tests/`.

Tests aren't safety nets here; they're the filter. A passing property
*corroborates* the claim. A shrunk Hegel counterexample *falsifies* it
and forces a design conversation. Three real shrinks have been resolved
this way, captured in card frontmatter.

The `cargo test` in this repo is the act of running the filter.

## Reading the repository

| File / directory          | What it is                                                  |
| ------------------------- | ----------------------------------------------------------- |
| `SPEC.md`                 | The 17-section falsifiable spec.                            |
| `hypotheses/index.md`     | Audit table — every spec claim mapped to card and test.     |
| `hypotheses/<id>.md`      | One claim per card; class A / B-stat / C / D + status.      |
| `crates/cosaci-*/`        | Five focused libraries.                                     |
| `bins/cosaci-*/`          | Three binaries: coordinator, agent, demo.                   |
| `tests/`                  | Property tests; one file per hypothesis card.               |
| `benches/hot_paths.rs`    | Criterion baselines on the trust-chain hot paths.           |
| `docs/ARCHITECTURE.md`    | Layered model, trust chain, dep graph, primitive choices.   |
| `docs/ROADMAP.md`         | v0.2 / v0.3 / v1.0 milestones and issue lists.              |
| `CONTRIBUTING.md`         | The bar for new contributions.                              |
| `CHANGELOG.md`            | Per-release detail.                                         |

## License

Dual-licensed under either of:

- Apache License, Version 2.0 (`LICENSE-APACHE`)
- MIT license (`LICENSE-MIT`)

at your option.
