---
id: crash-recovery-soundness
class: A
section: §10.5
status: passing
test: tests/crash_recovery_soundness.rs
depends_on: serde_json + tempfile (#51)
---

# Crash-recovery soundness

Issue #51's pure-data half: every externally-visible job-state
transition appends one line to the journal, fsync per record. On
restart, replay the journal to reconstruct in-flight state. The
property: for any sequence of valid transitions and any single
crash point, the post-restart `JournalState` is exactly what a
non-crashed run would have produced.

The coordinator-side integration (call `journal.append()` at every
transition + replay on startup) is a follow-on PR; this card
locks down the algebra that integration relies on.

## Statement

For any sequence of `JournalEntry` values and any prefix length
`k ∈ [0, entries.len()]`:

1. **Append + replay round-trips** byte-for-byte. After
   `journal.append()` for each entry in `entries[..k]`,
   `replay(path)` returns those k entries in append order. (The
   final unflushed buffer-or-bust write hasn't occurred yet, so
   the file's complete; we don't simulate torn writes here.)

2. **Pure reconstruction agrees with disk replay.**
   `reconstruct_state(&replay(path))` equals `reconstruct_state(&entries[..k])`.

3. **Lifecycle progression is monotone.** A job's state moves
   through {Submitted → InFlight → AggregatedNotAnchored →
   Anchored}; the reconstruction never moves a job backwards
   when entries arrive in lifecycle order.

4. **Submitted/InFlight jobs surface in `pending_re_run`.** A job
   in those states (per the reconstruction) is reported by
   `pending_re_run()`.

5. **AggregatedNotAnchored jobs surface in `pending_re_anchor`.**
   A job aggregated but not anchored is reported by
   `pending_re_anchor()`.

6. **Anchored jobs surface in `anchored_jobs`.** A job whose final
   entry is `Anchored` shows up in `anchored_jobs()`.

7. **Torn-write tolerance.** A journal file ending in a
   half-written line (truncated mid-JSON) yields the valid prefix
   on replay; the half-line is silently skipped. This is the
   `kill -9` semantics.

## Class

**A** — pure data + JSON serde + sequential append/replay. No
clocks; no concurrency in the hot path (the append-fsync is
sequential per writer).

## Falsification candidates

- Forgetting `sync_data` after `write_all` — Property 1 still
  passes in tests but the property fails under real `kill -9`
  (the kernel buffers the write). The fsync is verified by code
  inspection, not by the test (we can't simulate kernel-buffer
  loss in-process). A future C-class "real-fsync" test could.
- A non-deterministic serialization (e.g. HashMap iteration in
  the JSON output) — Property 2 catches it: the JSON written
  doesn't match what `serde_json::from_str` parses back.
- Missing `Anchored` handling in `reconstruct_state` — Property
  6 catches it.
- Treating a torn final write as a parse error rather than a
  skip — Property 7 catches it.

## Coverage

- `replay_round_trips_appended_entries` — Property 1
- `pure_reconstruct_matches_disk_replay` — Property 2
- `submitted_to_inflight_to_aggregated_to_anchored` — Property 3
- `pending_re_run_contains_submitted_and_inflight` — Property 4
- `pending_re_anchor_contains_aggregated_not_anchored` — Property 5
- `anchored_jobs_contains_anchored` — Property 6
- `torn_final_write_is_skipped` — Property 7
- `smoke_full_lifecycle_through_journal` (deterministic) — sanity

## Out of scope (follow-on)

- **Coordinator integration.** Wiring `journal.append()` into
  `run_one_job` at every state transition + replay on startup.
  Touches `bins/cosaci-coordinator/src/main.rs`.
- **Checkpointing + journal truncation.** Issue #51's "default
  every K transitions" requirement; the unbounded-growth
  mitigation. Lands as a follow-on once the integration is in
  place and we have a real signal of journal size.
- **`--journal <path>` flag** on coord. Lands with the integration.
- **RUNBOOK §5 update** ("disaster recovery") — replaces the
  current PARTIAL stub with the concrete replay procedure once
  the integration ships.
