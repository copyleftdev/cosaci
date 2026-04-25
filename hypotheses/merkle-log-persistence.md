---
id: merkle-log-persistence
source: SPEC.md §10.5
class: A
status: encoded
test: tests/merkle_log_persistence.rs
depends_on:
  - merkle-log-append-only
introduced_by: issue/33
---

# Merkle log persistence

A `FileStore`-backed `MerkleLog` survives process termination: dropping
the in-memory `MerkleLog` and reopening from the same path produces a
log with byte-identical entries and an identical Merkle root.

## Falsifiable claim

For any sequence of `n` entries `[e_0, e_1, …, e_{n-1}]` appended
via `MerkleLog::<FileStore>::append`:

1. **Entry-recovery soundness** — after the in-memory `MerkleLog` is
   dropped (modeling process termination) and a fresh
   `MerkleLog::<FileStore>::open(path)` is constructed against the
   same path, `entry_at(i)` returns `Some(e_i)` for every
   `0 ≤ i < n`.
2. **Root invariance under restart** — the root of the recovered log
   equals the root computed before the drop:
   `MerkleLog::<FileStore>::open(path)?.root() == previous_root`.
3. **Length preservation** — `len()` after recovery equals the count
   of `Ok` returns from `append` calls before the drop.
4. **Append idempotence under crash** — if `append(e)` returned `Ok`,
   then after recovery the log contains `e` at the position
   `append` returned. (This depends on `sync_data` semantics —
   the OS guarantees the data is on disk when `sync_data` returns
   on POSIX-compliant filesystems. Buggy filesystems / power loss
   without battery-backed cache are out of scope; that's hardware,
   not the algebra.)

## Why it's load-bearing

A coordinator that loses its Merkle log on restart loses every
attestation it ever anchored. Verifiers holding inclusion proofs
issued before the crash can no longer verify them — the root
they proved against doesn't exist anymore. The whole "tamper-
evident provenance" promise rests on the log surviving operational
events.

This is the foundation for #44 (output retrieval API) — without
durable anchors, the read API has nothing to read. It's also a
prerequisite for #45 (enrollment) and #51 (job-queue durability),
which need the same Store-trait abstraction extended to other
state.

## Test surface

`tests/merkle_log_persistence.rs`:

1. **Append, drop, reopen** — append n random entries, drop the log,
   reopen → assert content, root, and length all match.
2. **Mid-stream reopen** — append k entries, drop, reopen, append
   `n - k` more → final log must match a single uninterrupted-append
   sequence over the same n entries.
3. **Empty log persistence** — open an empty file-backed log, drop
   without appending, reopen → log is empty, root is `None`.
4. **Corrupt-file detection** — a file whose size isn't a multiple
   of 32 fails `open` with `InvalidData` rather than silently
   loading partial state.

## Out-of-scope

- **Concurrent appends from multiple processes** — `FileStore`
  assumes single-writer. Multi-writer durability is a separate
  primitive (file locking + leader election); the coordinator is
  the sole writer in the current architecture.
- **Filesystem-level torn writes** — partial writes from a hard
  reset mid-`write_all`. The 32-byte record size is below typical
  disk block sizes, but POSIX doesn't guarantee write atomicity
  for `write_all`. A production deployment would either layer
  checksumming on top or use a journal-style write protocol;
  v0.3 trusts the filesystem for this.
- **Backup / archival** — out of scope; the operator's runbook
  (#48) covers this.
