---
id: source-fetch-determinism
source: SPEC.md §6.2.1
class: A
status: passing
test: tests/source_fetch_determinism.rs
depends_on:
  - pipeline-determinism
introduced_by: issue/40
---

# Source-fetch determinism

Two runners executing `Step::SourceFetch` against an equivalent
working tree must produce equal `tree_hash` values, and a runner
that resolved a moving branch to a different commit than its
peers must produce a different `output_hash`.

## Falsifiable claim

The deterministic core is the pure tree-hashing primitive
[`source_fetch::hash_working_tree`]. For any directory tree `t`:

- **Path-set sensitivity** — adding or removing a file changes
  `hash_working_tree(t)`.
- **Path sensitivity** — renaming a file (changing its relative
  path) changes `hash_working_tree(t)`.
- **Content sensitivity** — changing one byte of any file's
  content changes `hash_working_tree(t)`.
- **Mode sensitivity** (Unix) — toggling a file's executable bit
  changes `hash_working_tree(t)`. Non-`u+x`-bit permission
  changes do not change the hash, by design — only the git-
  canonical two-mode model is recorded.
- **Order independence** — files written to disk in arbitrary
  order produce the same hash. (The walker reads in directory
  order, but the hash is computed over a sorted record stream.)
- **Exclusion respected** — `.git` (or any directory in
  `exclude_dirs`) is not part of the hash. Two clones that differ
  only in their `.git` packing produce equal `tree_hash`s.

The composed `output_hash` (used as the step's contribution to
`final_artifact_hash`) binds both `resolved_sha` and `tree_hash`,
so a runner whose branch resolution diverged from its peers
produces a divergent `output_hash` even if the trees coincidentally
agree.

## Why the network-bound `execute_source_fetch` is not the falsifiable
## claim

The actual `git clone` is not a property a Hegel rule can falsify
without standing up a network: `clone` may fail, the upstream may
move, and a property test that depends on either is not a
property test. The `hash_working_tree` primitive is the
falsifiable core; the integration test `tests/source_fetch_integration.rs`
exercises `execute_source_fetch` against a `git init`-built local
fixture to confirm the wiring, not the property.

## Out of scope (follow-on)

- Symlink handling. v0.3 skips symlinks (a determinism hazard;
  rarely needed in CI workloads).
- CRLF normalization across platforms. v0.3 hashes raw bytes.
- Resource bounds (max clone size, wall clock). The DSL carries
  `Limits` but the source-fetch executor doesn't consult them
  yet — the wall-clock bound matters most and lands alongside
  `ExecNative`'s real enforcement (#43 follow-on for non-WASM
  steps).
- Branch-moves-mid-round detection at the *coordinator* layer.
  The step exposes `resolved_sha` so divergence is observable,
  but the coord doesn't yet aggregate per-runner SHAs into a
  separate divergence channel — a runner that resolves to a
  different commit just produces a divergent `artifact_hash`
  and the existing slashing-faithfulness machinery handles it.
