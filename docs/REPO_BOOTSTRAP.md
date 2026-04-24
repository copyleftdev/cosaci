# Repo Bootstrap

Step-by-step `gh` commands to take this local working tree to a
private GitHub repo at `copyleftdev/cosaci` with labels, milestones,
and the v0.2 issue list filed.

Prereqs:
- `gh` CLI installed and authenticated (`gh auth status`).
- Membership in the `copyleftdev` org with permission to create repos.

## 1. Create the repo

From the `cosaCI/` working tree:

```bash
gh repo create copyleftdev/cosaci \
    --private \
    --source=. \
    --remote=origin \
    --description="Distributed attested CI mesh — property-tested at every layer" \
    --homepage="https://github.com/copyleftdev/cosaci"
```

This pushes the local `main` branch (six commits) to the new private
repo.

## 2. Apply labels

```bash
# kind/*
gh label create "kind/bug"      --color "d73a4a" --description "Something isn't working"
gh label create "kind/feat"     --color "a2eeef" --description "New feature or capability"
gh label create "kind/refactor" --color "f9d0c4" --description "Code restructure with no behavior change"
gh label create "kind/chore"    --color "fef2c0" --description "Build / tooling / dep maintenance"
gh label create "kind/docs"     --color "0075ca" --description "Documentation"
gh label create "kind/test"     --color "bfd4f2" --description "Tests / fixtures / harnesses"
gh label create "kind/perf"     --color "f7c6c7" --description "Performance"

# priority/*
gh label create "priority/P0"   --color "b60205" --description "Blocker — drop everything"
gh label create "priority/P1"   --color "d93f0b" --description "Must ship in current milestone"
gh label create "priority/P2"   --color "fbca04" --description "Should ship in current milestone"
gh label create "priority/P3"   --color "0e8a16" --description "Nice to have / next milestone"

# area/*
gh label create "area/core"        --color "5319e7" --description "Pure algebra + crypto primitives"
gh label create "area/state"       --color "5319e7" --description "Stateful subsystems"
gh label create "area/protocol"    --color "5319e7" --description "Wire protocol + transport"
gh label create "area/vrf"         --color "5319e7" --description "VRF subsystem"
gh label create "area/wasm"        --color "5319e7" --description "WASM runtime"
gh label create "area/coordinator" --color "1d76db" --description "Coordinator binary"
gh label create "area/agent"       --color "1d76db" --description "Agent binary"
gh label create "area/demo"        --color "1d76db" --description "Demo binaries"
gh label create "area/bin"         --color "1d76db" --description "Cross-binary concerns"
gh label create "area/ci"          --color "c5def5" --description "CI workflows"
gh label create "area/build"       --color "c5def5" --description "Build / clippy / cargo deny"
gh label create "area/release"     --color "c5def5" --description "Versioning / changelog / publish"

# status/*
gh label create "status/blocked"       --color "000000" --description "Blocked on something else"
gh label create "status/in-progress"   --color "fbca04" --description "Active work"
gh label create "status/needs-review"  --color "0e8a16" --description "Waiting on review"

# Conventional
gh label create "good first issue" --color "7057ff" --description "Suitable for newcomers"
gh label create "help wanted"      --color "008672" --description "Needs help to land"
gh label create "flaky"            --color "e99695" --description "Test fails intermittently"
```

GitHub creates a default set of labels on every new repo
(`bug`, `documentation`, `enhancement`, etc.). Delete those once
the new ones are in place:

```bash
for old in "bug" "documentation" "duplicate" "enhancement" "good first issue" "help wanted" "invalid" "question" "wontfix"; do
    gh label delete "$old" --yes 2>/dev/null
done
```

(The "good first issue" / "help wanted" deletes-and-recreates is
intentional — we set our own description.)

## 3. Create milestones

```bash
gh api repos/copyleftdev/cosaci/milestones -X POST \
    -f title="v0.2.0 — Workspace + Hardening" \
    -f description="Workspace split + audit gates + protocol hardening + docs pass." \
    -f state="open"

gh api repos/copyleftdev/cosaci/milestones -X POST \
    -f title="v0.3.0 — Production-ready binaries" \
    -f description="Real-world workflow + persistent state + slashing + remaining test harnesses." \
    -f state="open"

gh api repos/copyleftdev/cosaci/milestones -X POST \
    -f title="v1.0.0 — Public beta" \
    -f description="Stable spec + operator runbook + crates.io publish + security audit." \
    -f state="open"
```

## 4. File the v0.2 issues

The 15 issues from `docs/ROADMAP.md` § v0.2.0. Adjust title/body as
needed; the labels and milestone are pre-set.

```bash
M="v0.2.0 — Workspace + Hardening"

gh issue create -m "$M" -l "kind/refactor,priority/P1,area/build" \
  -t "Workspace skeleton (no module moves yet)" \
  -b "Set up the Cargo workspace per docs/WORKSPACE_LAYOUT.md PR 1.

- [ ] Create crates/ and bins/ directories with stub Cargo.toml files.
- [ ] Wire up [workspace] in the top-level Cargo.toml with members + shared dependencies.
- [ ] Mark every member publish = false until v1.0.
- [ ] Confirm cargo build and cargo test produce identical artifacts to before.
- [ ] cargo metadata reflects the new workspace structure.

Blocks: #2, #3, #4."

gh issue create -m "$M" -l "kind/refactor,priority/P1,area/core,area/state" \
  -t "Move cosaci-core + cosaci-state modules" \
  -b "PR 2 of the workspace split. See docs/WORKSPACE_LAYOUT.md for the module → crate mapping.

- [ ] Move clock, signing, attestation, quorum, confidentiality, capabilities, gossip, bloom, flake, reputation, status, verifier, merkle_log into cosaci-core.
- [ ] Move lease, registry, aggregator, partition, replicated_cluster, replay, rate_limit, sharding, sharding_handoff into cosaci-state.
- [ ] Re-export from the old cosaci package so existing tests keep compiling.
- [ ] All 32 test files still pass.

Blocks #3."

gh issue create -m "$M" -l "kind/refactor,priority/P1,area/vrf,area/wasm,area/protocol" \
  -t "Isolate vrf, wasm, and protocol into dedicated crates" \
  -b "PR 3 of the workspace split.

- [ ] vrf.rs → cosaci-vrf
- [ ] wasm_runtime.rs → cosaci-wasm
- [ ] proto.rs + tls.rs → cosaci-protocol
- [ ] Verify cargo build -p cosaci-core does NOT compile wasmtime or schnorrkel.
- [ ] Bin compile times measurably improved when their deps are excluded.

Blocks #4."

gh issue create -m "$M" -l "kind/refactor,priority/P1,area/bin" \
  -t "Move binaries to dedicated bin crates" \
  -b "PR 4 of the workspace split.

- [ ] src/bin/coordinator.rs → bins/cosaci-coordinator/src/main.rs
- [ ] src/bin/agent.rs → bins/cosaci-agent/src/main.rs
- [ ] src/bin/{demo,demo_networked}.rs → bins/cosaci-demo/src/bin/
- [ ] cargo run -p cosaci-coordinator and cargo run -p cosaci-demo --bin demo_networked still work end-to-end.
- [ ] Original src/bin/ deleted."

gh issue create -m "$M" -l "kind/feat,priority/P1,area/coordinator" \
  -t "Persistent coordinator: loop instead of one-shot" \
  -b "Currently the coordinator handles one job and exits. v0.2 needs:

- [ ] Listen forever on the bound address.
- [ ] Maintain a job queue; assign jobs to committees from the queue.
- [ ] Per-job state isolated and cleaned up after completion.
- [ ] Graceful SIGTERM handling: drain in-flight, decline new jobs, exit.
- [ ] Reuse open agent connections across jobs."

gh issue create -m "$M" -l "kind/feat,priority/P1,area/protocol,area/wasm" \
  -t "Real WASM payloads carried in Assign envelopes" \
  -b "Current Assign carries (a, b) for the canned add module. v0.2:

- [ ] Assign carries a Vec<u8> WASM module + serialized input args (CBOR).
- [ ] Agent compiles + runs the supplied module via wasmtime.
- [ ] Output hash includes the module hash so different modules don't collide.
- [ ] Canned-WAT becomes an example, not a primitive.
- [ ] Document supported module shape (entry point, ABI)."

gh issue create -m "$M" -l "kind/feat,priority/P1,area/vrf,area/coordinator" \
  -t "VRF-proof committee verification end-to-end" \
  -b "Today the coordinator uses SHA-256(vrf_pk||seed) lex-min for committee selection — verifiable but not VRF-proof-checked. v0.2:

- [ ] Register envelope includes a VRFProof for a fixed challenge string.
- [ ] Coordinator verifies the proof against the agent's claimed VRF pubkey before counting them.
- [ ] Committee selection switches to VRF output (not pubkey-hash).
- [ ] Each agent in the committee re-submits its VRF output + proof for the job seed.
- [ ] Coordinator verifies all proofs match the selection rule."

gh issue create -m "$M" -l "kind/feat,priority/P2,area/protocol" \
  -t "Cert rotation + CRL/OCSP revocation hooks" \
  -b "Closes the deferred half of mtls-enforcement.

- [ ] Hot-rotate server cert: existing connections survive; new connections use new cert.
- [ ] Client cert revocation list distributed to coordinator; verifier rejects revoked certs.
- [ ] Property tests for both: connections-to-revoked-cert reject; mid-session rotation preserves in-flight state."

gh issue create -m "$M" -l "kind/chore,priority/P1,area/build" \
  -t "cargo clippy --all-targets -- -D clippy::pedantic clean" \
  -b "Audit gate.

- [ ] All pedantic findings either fixed or #[allow]-annotated with a comment explaining why.
- [ ] CI fails on any new pedantic finding.
- [ ] rust-claude pre-write hook is consistent with the lint level."

gh issue create -m "$M" -l "kind/chore,priority/P1,area/build" \
  -t "cargo deny check integrated" \
  -b "Add deny.toml.

- [ ] License policy: MIT / Apache-2.0 / BSD-3-Clause / ISC allowed; everything else needs review.
- [ ] Advisories: deny known security advisories; per-crate version pins for unfixed.
- [ ] Sources: allow crates.io and the rust-lang git mirrors only.
- [ ] CI fails on policy violations."

gh issue create -m "$M" -l "kind/chore,priority/P2,area/build" \
  -t "Add .rustfmt.toml + cargo fmt --check in CI" \
  -b "Format consistency.

- [ ] .rustfmt.toml with project-wide settings (edition 2024, max_width 100).
- [ ] Run cargo fmt over the workspace once.
- [ ] CI runs cargo fmt --check on every PR."

gh issue create -m "$M" -l "kind/docs,priority/P2,area/core,area/state" \
  -t "Doc coverage: #![deny(missing_docs)] on every public item" \
  -b "Today most pub items have doc comments; this issue is to enforce.

- [ ] Add #![deny(missing_docs)] to each library crate root.
- [ ] Fix or //! - prefix every undocumented public item.
- [ ] cargo doc --workspace --no-deps clean."

gh issue create -m "$M" -l "kind/chore,priority/P1,area/ci" \
  -t "GitHub Actions CI workflow" \
  -b "Standard Rust CI. .github/workflows/ci.yml:

- [ ] cargo test --workspace on Ubuntu (stable + MSRV).
- [ ] cargo bench --no-run --workspace (compile only).
- [ ] cargo clippy --all-targets -- -D warnings -D clippy::pedantic.
- [ ] cargo fmt --check.
- [ ] cargo deny check.
- [ ] cargo doc --workspace --no-deps -D warnings.
- [ ] Cache target/ between runs."

gh issue create -m "$M" -l "kind/docs,priority/P2,area/release" \
  -t "CHANGELOG.md + semver discipline" \
  -b "Document the version policy.

- [ ] Top-level CHANGELOG.md following Keep a Changelog format.
- [ ] All crates bump together until v1.0; minor for breaking, patch for non-breaking.
- [ ] CONTRIBUTING.md references the policy.
- [ ] First entry: v0.2.0 - workspace split."

gh issue create -m "$M" -l "kind/chore,priority/P2,area/release" \
  -t "Crate metadata + initial release prep" \
  -b "Polish for the v0.2 release.

- [ ] Each Cargo.toml: description, keywords, categories, readme.
- [ ] publish = false on every crate (we ship via GitHub releases until v1).
- [ ] Top-level README.md with quickstart + link to docs/.
- [ ] LICENSE-MIT + LICENSE-APACHE files."
```

## 5. Verify

```bash
gh repo view copyleftdev/cosaci
gh label list
gh api repos/copyleftdev/cosaci/milestones | jq '.[] | {title, open_issues}'
gh issue list -m "v0.2.0 — Workspace + Hardening" --limit 30
```

Expected: 15 issues in v0.2.0, all with proper labels.

## 6. Optional: protect main + require status checks

```bash
gh api repos/copyleftdev/cosaci/branches/main/protection \
    -X PUT \
    -F required_status_checks.strict=true \
    -F required_status_checks.contexts[]="ci" \
    -F enforce_admins=false \
    -F required_pull_request_reviews.required_approving_review_count=1 \
    -F restrictions=
```

## Notes

- The `gh repo create --source=. --remote=origin` flow in step 1
  pushes the existing local commits to the new repo. Confirm the
  push log shows commits `7094e19` through `da4a81c` as
  `origin/main`.

- The v0.3 issues from `docs/ROADMAP.md` are intentionally *not* filed
  during bootstrap; file them at v0.2.0 wrap-up so the v0.3 backlog
  isn't a distraction.
