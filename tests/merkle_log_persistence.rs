//! Property-based tests for `cosaci::merkle_log::FileStore`.
//!
//! Encodes the falsifiable claims of `hypotheses/merkle-log-persistence.md`
//! (issue #33, class A). The four properties:
//!
//!   1. Append, drop, reopen — entries + root + length all preserved.
//!   2. Mid-stream reopen — appending across a drop produces the same
//!      log as a single uninterrupted-append run.
//!   3. Empty-log persistence — an opened-then-dropped empty log
//!      reopens as empty.
//!   4. Corrupt-file detection — a non-multiple-of-32 file size fails
//!      `open` with `InvalidData` rather than silently loading
//!      partial state.

use std::fs;

use cosaci::merkle_log::{FileStore, Hash, MerkleLog};
use hegel::{TestCase, generators};
use tempfile::tempdir;

fn draw_hash(tc: &TestCase) -> Hash {
    let v: Vec<u8> = tc.draw(generators::binary().min_size(32).max_size(32));
    let mut h = [0_u8; 32];
    h.copy_from_slice(&v);
    h
}

fn draw_entries(tc: &TestCase, max: usize) -> Vec<Hash> {
    let n = tc.draw(generators::integers::<usize>().min_value(0).max_value(max));
    (0..n).map(|_| draw_hash(tc)).collect()
}

// ----------------------------------------------------------------------------
// Property 1 — append, drop, reopen.
// ----------------------------------------------------------------------------
#[hegel::test]
fn append_then_reopen_preserves_log(tc: TestCase) {
    let entries = draw_entries(&tc, 32);
    let dir = tempdir().expect("temp dir");
    let path = dir.path().join("log");

    let root_before = {
        let mut log = MerkleLog::<FileStore>::open(&path).expect("open empty");
        for e in &entries {
            log.append(*e).expect("append");
        }
        log.root()
    }; // log dropped here — simulates process termination

    let log = MerkleLog::<FileStore>::open(&path).expect("reopen");
    assert_eq!(log.len(), entries.len() as u64, "len mismatch after reopen");
    for (i, e) in entries.iter().enumerate() {
        assert_eq!(
            log.entry_at(i as u64),
            Some(*e),
            "entry {i} mismatch after reopen"
        );
    }
    assert_eq!(log.root(), root_before, "root changed across drop+reopen");
}

// ----------------------------------------------------------------------------
// Property 2 — mid-stream reopen.
// ----------------------------------------------------------------------------
#[hegel::test]
fn mid_stream_reopen_matches_uninterrupted_appends(tc: TestCase) {
    let entries = draw_entries(&tc, 32);
    if entries.is_empty() {
        return; // nothing to split
    }
    let split = tc.draw(
        generators::integers::<usize>()
            .min_value(0)
            .max_value(entries.len()),
    );
    let dir = tempdir().expect("temp dir");
    let path = dir.path().join("log");

    // Run 1: split append, drop, append rest.
    {
        let mut log = MerkleLog::<FileStore>::open(&path).expect("open");
        for e in &entries[..split] {
            log.append(*e).expect("append");
        }
    }
    {
        let mut log = MerkleLog::<FileStore>::open(&path).expect("reopen");
        for e in &entries[split..] {
            log.append(*e).expect("append after reopen");
        }
    }
    let split_log = MerkleLog::<FileStore>::open(&path).expect("final open");

    // Run 2: same entries, single uninterrupted append run, separate path.
    let dir2 = tempdir().expect("temp dir 2");
    let path2 = dir2.path().join("log");
    {
        let mut log = MerkleLog::<FileStore>::open(&path2).expect("open");
        for e in &entries {
            log.append(*e).expect("append");
        }
    }
    let mono_log = MerkleLog::<FileStore>::open(&path2).expect("final open 2");

    assert_eq!(split_log.len(), mono_log.len());
    assert_eq!(
        split_log.root(),
        mono_log.root(),
        "root differs across split vs mono"
    );
    for i in 0..split_log.len() {
        assert_eq!(
            split_log.entry_at(i),
            mono_log.entry_at(i),
            "entry {i} differs across split vs mono"
        );
    }
}

// ----------------------------------------------------------------------------
// Property 3 — empty log persistence.
// ----------------------------------------------------------------------------
#[hegel::test]
fn empty_log_persistence(_tc: TestCase) {
    let dir = tempdir().expect("temp dir");
    let path = dir.path().join("log");

    {
        let log = MerkleLog::<FileStore>::open(&path).expect("open");
        assert!(log.is_empty());
        assert_eq!(log.root(), None);
    } // drop without appending

    let log = MerkleLog::<FileStore>::open(&path).expect("reopen");
    assert!(log.is_empty(), "empty log gained entries across drop");
    assert_eq!(log.root(), None);
    assert_eq!(log.len(), 0);
}

// ----------------------------------------------------------------------------
// Property 4 — corrupt-file detection.
//
// A file whose size isn't a multiple of 32 indicates a torn write or
// external corruption. Open must fail with InvalidData rather than
// silently loading the truncated prefix.
// ----------------------------------------------------------------------------
#[hegel::test]
fn corrupt_file_rejected(tc: TestCase) {
    let entries = draw_entries(&tc, 8);
    let dir = tempdir().expect("temp dir");
    let path = dir.path().join("log");

    // Write a valid log first.
    {
        let mut log = MerkleLog::<FileStore>::open(&path).expect("open");
        for e in &entries {
            log.append(*e).expect("append");
        }
    }

    // Append `extra_bytes` non-aligned bytes to corrupt the size.
    let extra_bytes = tc.draw(generators::integers::<usize>().min_value(1).max_value(31));
    let mut content = fs::read(&path).expect("read");
    content.extend(std::iter::repeat_n(0xab_u8, extra_bytes));
    fs::write(&path, &content).expect("write corrupt");

    let result = MerkleLog::<FileStore>::open(&path);
    assert!(
        result.is_err(),
        "corrupt file (size not %32) should reject; got Ok with len {}",
        result.map(|l| l.len()).unwrap_or(0)
    );
    let err = result.err().unwrap();
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::InvalidData,
        "expected InvalidData, got {err:?}"
    );
}
