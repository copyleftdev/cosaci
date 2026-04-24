<!--
Thanks for the PR. Fill in the sections below — short bullets are fine.
-->

## What this changes

<!-- One paragraph. What does this PR do, and why now? -->

## How it was tested

- [ ] Existing test suite still green: `cargo test --workspace`
- [ ] Lint clean: `cargo clippy --all-targets -- -D warnings -D clippy::pedantic`
- [ ] Format clean: `cargo fmt --check`
- [ ] Audit clean (if deps changed): `cargo deny check`

## Hypothesis cards affected

<!--
If this PR changes behavior covered by a hypothesis card, list it.
If a new claim is introduced, the card should land in this PR (or a
prerequisite PR) before the code that implements it.
-->

- `hypotheses/<id>.md` — <state-of-claim>

## Hegel shrinks

<!--
Did Hegel surface any new shrunk counterexamples during development?
Capturing the shape of what the filter rejected helps reviewers and
future-you. Three shrinks have been resolved on `main` so far; this
list is how we keep that history visible.
-->

- [ ] No new shrinks
- [ ] Shrink resolved (describe):

## Checklist

- [ ] Conventional commit message ([kind] short summary in imperative).
- [ ] CHANGELOG.md updated (if user-visible change).
- [ ] Linked to the GitHub issue (`Closes #N`).
- [ ] No `unwrap()` in library code (`expect("...")` with a sentence is fine).
- [ ] No `println!()` in library code (use `tracing` or return a value).
- [ ] All `unsafe` blocks have `// SAFETY:` comments.
