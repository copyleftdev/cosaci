---
id: exec-native-determinism
source: SPEC.md §6.2 / §6.3
class: A
status: passing
test: tests/exec_native.rs
depends_on:
  - pipeline-determinism
introduced_by: issue/107 PR 1 of N
---

# ExecNative determinism (plain executor)

`Step::ExecNative { command, env, limits }` runs a native
process with a fixed argv and a deterministic environment.
PR 1 of N (this card) lands the **plain executor** — no
sandbox. Subsequent PRs layer cgroups v2 limits, mount-
namespace isolation, and egress enforcement; each adds
falsifiable claims of its own without disturbing the
determinism contract here.

## Determinism contract

For any `(command, env, limits)`, two runners executing the
same `Step::ExecNative` against equal external state produce
**byte-equal `StepOutput`s**. The output components:

- `step_index` — purely positional.
- `status` — function of (exit code, walltime kill, spawn
  error kind).
- `output_hash` — bound to:
  - **Success / Failed**: `(step bytes, marker, exit_code,
    sha256(stdout), sha256(stderr))`.
  - **LimitExceeded { Wall }**: `(step bytes, LimitKind::Wall)`.
    Walltime-killed runs intentionally do **not** hash the
    captured bytes — see "Why captured bytes are excluded
    on timeout" below.
  - **Failed (spawn error)**: `(step bytes, marker,
    io::ErrorKind as i32)`. Same kind of failure ⇒ same hash.

Walltime, PID, and memory consumed are **not** in the hash.
Two runners on different hardware that both succeed with
the same exit + the same captured bytes produce identical
results.

## Falsifiable claims

For any `Step::ExecNative`:

- **Same command, same hash** — running an identical
  `Step::ExecNative` twice yields byte-equal `PipelineResult`s,
  including `final_artifact_hash`.
- **Distinct stdout, distinct hash** — two `Step::ExecNative`s
  whose only difference is the stdout produced by the child
  yield distinct step `output_hash`es and distinct
  `final_artifact_hash`es. The executor cannot collapse
  different observations into the same canonical bytes.
- **Spawn-failure determinism** — a `Step::ExecNative` whose
  command doesn't exist returns `StepStatus::Failed` and a
  deterministic `output_hash` bound to `io::ErrorKind::NotFound`.
  Two runners hitting the same spawn failure produce the
  same hash; runners that successfully spawn produce a
  distinct (Success/Failed-with-exit-code) hash.
- **Empty-command determinism** — a `Step::ExecNative` with
  `command.is_empty()` returns `Failed` deterministically.
- **Non-zero exit is Failed** — a child that exits with a
  non-zero status returns `StepStatus::Failed` and the exit
  code is bound into the hash.
- **Wall-timeout kills the child** — a `Step::ExecNative`
  with `limits.wall_seconds = N` whose child runs longer
  than `N` seconds is killed within `N + WALL_POLL_INTERVAL`
  (50ms) of the deadline; the step terminates as
  `StepStatus::LimitExceeded { which: LimitKind::Wall }`.

## What this PR does not enforce

- **cpu_seconds / memory_mb** — both are accepted on
  `Limits` but ignored by the plain executor. cgroups v2
  wiring lands in #107 PR 2 of N.
- **Filesystem isolation** — the child sees the parent's
  full filesystem. Mount-namespace + read-only rootfs lands
  in #107 PR 3 of N.
- **Egress enforcement** — `limits.network` is accepted but
  not enforced at the kernel level. netns + iptables lands
  in #107 PR 4 of N (and gets its own C-class card,
  `egress-enforcement-faithfulness`).

## Why captured bytes are excluded on timeout

A killed child whose grandchildren survive (e.g.
`sh -c 'sleep 5'` reparents `sleep` to init) keeps our
stdout/stderr pipes alive — the reparented child inherits
them. If we waited for the reader threads to drain on the
walltime path, we'd block well past `wall_seconds`.

Instead the timeout path detaches the reader threads and
hashes only `(step bytes, LimitKind::Wall)`. That keeps
walltime determinism crisp: any two runners that hit the
same walltime on the same step produce byte-equal hashes,
regardless of how much partial output the child managed to
emit before being killed. The detached reader threads exit
when the reparented children eventually close their pipe
ends; in steady state the leak is bounded.

PR 4 of N (process-tree kill via cgroup-kill) makes the
reparenting a non-issue — the whole tree dies together —
and may revisit whether captured prefixes get hashed on the
timeout path. This card is the v0.5 contract.

## Why this is class A

Each property is a pointwise statement over a single
`execute_pipeline(p)` call (or a deterministically-ordered
pair of calls). No averaging. The Hegel-like assertions in
`tests/exec_native.rs` are pointwise.

## Out of scope

- cgroups v2 cpu/memory enforcement — #107 PR 2 of N.
- Mount namespace + read-only rootfs — #107 PR 3 of N.
- Egress enforcement at the kernel level — #107 PR 4 of N.
- macOS native exec — Linux-only for v0.5; macOS would use
  `sandbox-exec` (Apple-deprecated). Tests are gated
  `#[cfg(unix)]` because the canned commands `/bin/echo`,
  `/bin/sh`, `sleep` are POSIX-shaped, not because the
  executor itself requires Unix.
