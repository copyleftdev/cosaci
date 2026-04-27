# Contributing to CosaCI

Thanks for taking an interest. CosaCI is an experimental, falsifiable-spec
project — every contribution should preserve that property. The rest of this
document is the bar.

## Toolchain

The pinned toolchain is in `rust-toolchain.toml`. Rustup respects it
automatically; `cargo` uses the right `rustc` + `rustfmt` + `clippy` versions.
Don't bypass the pin — bumping it is a deliberate change.

## The four gates

Every PR is gated on these. Run them locally before pushing.

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings   # pedantic via workspace lints
cargo test --workspace
cargo deny check
```

Plus the smoke test, which CI runs over `demo_networked`:

```sh
cargo run -p cosaci-demo --bin demo_networked
```

### Local CI-equivalent script + pre-push hook

The same gates are wired up in `scripts/ci-local.sh`. Run on demand:

```sh
scripts/ci-local.sh           # full suite
FAST=1 scripts/ci-local.sh    # skip the slow `cargo test` step
```

Opt in to a pre-push hook so every `git push` runs the suite first
(skippable with `git push --no-verify`):

```sh
git config core.hooksPath .githooks
```

This is useful when you'd rather catch failures before they hit
GitHub Actions — and essential when Actions minutes are exhausted.

If a new public item lands, `#![deny(missing_docs)]` requires a doc comment
or the build fails — locally, not just in CI.

## Hypotheses + hegel

Every spec claim from `SPEC.md` is paired with a **hypothesis card** under
`hypotheses/` and a Hegel property test under `tests/`. The pattern:

1. Pick a claim. Read its card. If there isn't one, write it first —
   `hypotheses/index.md` is the source of truth for the audit trail.
2. Encode the claim as a `#[hegel::test]` (or `#[hegel::state_machine]`)
   property in `tests/<id>.rs`. Class A claims are pointwise universal;
   B-stat claims wrap an inner sample loop and assert an averaged
   guarantee; C claims are blocked-on infra.
3. Run it. **Get a counterexample first** if you can — Hegel's shrinker
   is the most useful design tool in the project. Three v0.1 shrinks
   pulled real bugs out of premature spec text.
4. Implement until it passes. Mark the card `status: passing` and
   reference the test path.

Don't add an implementation without a property. Don't add a property
without a hypothesis card.

## Versioning + bump policy

The project is pre-1.0; every crate in the workspace bumps together. The
rule is straightforward:

- **Breaking changes** → minor bump (e.g. `0.2.0` → `0.3.0`).
  Anything that changes the wire protocol, a public type signature, or a
  test's observable contract counts.
- **Non-breaking changes** → patch bump (e.g. `0.2.0` → `0.2.1`).
  Bug fixes, internal refactors, new tests, doc additions, dependency
  updates that don't change behavior.

The "minor for breaking" rule is the well-known semver-pre-1.0 inversion;
crates can't reasonably treat a 0.x bump as backwards-compatible, so we
flip the meaning. Once we cut v1.0, each crate versions independently
and conventional semver applies.

## Pre-release tagging

Pre-releases are marked with the `-alpha.N` / `-beta.N` suffix on
`workspace.package.version`:

- `0.X.0-alpha.N` — work in progress on the X milestone. The default
  shape — what's shipping today is `0.2.0-alpha.1`.
- `0.X.0-beta.N` — the milestone's checklist is closed and we're
  burning down review/CI/operational issues. No new features land.
- `0.X.0` — milestone shipped. Tag `vX.Y.Z` on `main`, write a release
  note pointing at the relevant `CHANGELOG.md` section.

CI runs against every tag matching `v*`; production deploys (when we
have any) pin to a specific tag.

## CHANGELOG discipline

Every user-visible change gets an entry in the `[Unreleased]` section
of `CHANGELOG.md` **as part of the PR that introduces it**. Entries are:

- Grouped by `Added` / `Changed` / `Deprecated` / `Removed` / `Fixed`
  / `Security`, in that order (Keep a Changelog convention).
- Reference the issue or PR number that introduced the change.
- Written from the user's perspective — what changed for someone
  reading our docs or pulling in a crate, not what changed in the
  codebase.

When the milestone closes, `[Unreleased]` is renamed to the new
`[X.Y.Z] — YYYY-MM-DD` heading and a fresh empty `[Unreleased]`
section is added below the top-of-file boilerplate.

## PR workflow

- One issue per PR. The PR title is the same as the issue title with
  `— closes #N` suffixed.
- The PR description starts with a `## Summary` of what changed and
  why, then a `## Test plan` checklist that maps to the four gates
  above.
- Stack PRs as needed. If your branch sits on top of an unmerged PR,
  rebase onto `main` after the parent merges before opening yours.

## What to ask in a code review

The reviewer's job is to ask, in order:

1. **Did the spec change?** If yes, was the matching hypothesis card
   updated and is `hypotheses/index.md` still accurate?
2. **Does every public item have a docstring?** The lint catches it,
   but a passing lint isn't always a useful sentence.
3. **Are the four gates green?** Read CI's deny output too — the
   advisory list is short and intentional.
4. **Could a future incident point at this PR?** If so, the commit
   message explains what was assumed and what would invalidate the
   assumption.
