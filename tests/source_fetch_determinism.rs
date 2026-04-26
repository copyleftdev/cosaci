//! Property tests for `cosaci_jobs::source_fetch`.
//!
//! Encodes the falsifiable claims of
//! `hypotheses/source-fetch-determinism.md` (issue #40, class A).
//!
//! These tests cover the *pure* tree-hashing primitive
//! [`hash_working_tree`]. The network-bound `execute_source_fetch`
//! lives in `tests/source_fetch_integration.rs`, which exercises the
//! plumbing against a `git init`-built local fixture.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use cosaci::jobs::source_fetch::{SourceFetchOutput, hash_working_tree, output_hash};
use hegel::{TestCase, generators};
use tempfile::tempdir;

// ----------------------------------------------------------------------------
// Hegel draw helpers
// ----------------------------------------------------------------------------

/// Draw a small set of "files" — each a `(rel_path, content)` pair —
/// suitable for materializing on disk and rehashing. We use `unique`
/// on the path component so the multiset and the path-set agree.
#[derive(Clone, Debug)]
struct DrawnFile {
    rel_path: String,
    content: Vec<u8>,
    executable: bool,
}

fn draw_files(tc: &TestCase) -> Vec<DrawnFile> {
    let n = tc.draw(generators::integers::<usize>().min_value(1).max_value(6));
    let mut files = Vec::with_capacity(n);
    let mut paths_seen = std::collections::HashSet::new();
    for _ in 0..n {
        // Synthesize a path from a few segments. Keeping the alphabet
        // tiny on purpose so Hegel reaches collision-prone shrinks.
        let depth = tc.draw(generators::integers::<usize>().min_value(1).max_value(2));
        let mut segs: Vec<String> = (0..depth)
            .map(|_| {
                let i = tc.draw(generators::integers::<u8>().min_value(0).max_value(7));
                format!("p{i}")
            })
            .collect();
        let leaf_i = tc.draw(generators::integers::<u8>().min_value(0).max_value(15));
        segs.push(format!("f{leaf_i}.txt"));
        let rel = segs.join("/");
        if !paths_seen.insert(rel.clone()) {
            // Skip duplicates — `unique` over the synthetic path
            // space is awkward to express in the imperative API.
            continue;
        }
        let content_len = tc.draw(generators::integers::<usize>().min_value(0).max_value(64));
        let content: Vec<u8> = tc.draw(
            generators::binary()
                .min_size(content_len)
                .max_size(content_len),
        );
        let executable = tc.draw(generators::booleans());
        files.push(DrawnFile {
            rel_path: rel,
            content,
            executable,
        });
    }
    files
}

fn materialize(root: &Path, files: &[DrawnFile]) {
    for f in files {
        let abs = root.join(&f.rel_path);
        if let Some(parent) = abs.parent() {
            fs::create_dir_all(parent).expect("mkdir -p");
        }
        let mut file = File::create(&abs).expect("create file");
        file.write_all(&f.content).expect("write content");
        #[cfg(unix)]
        if f.executable {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = file.metadata().expect("metadata").permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&abs, perms).expect("chmod");
        }
        #[cfg(not(unix))]
        let _ = f.executable;
    }
}

// ----------------------------------------------------------------------------
// Property 1 — Self-equality (within-runner determinism).
//
// Hashing the same tree twice produces equal hashes. This is the
// trivial-but-load-bearing baseline: if it fails, every other claim
// in this file is moot.
// ----------------------------------------------------------------------------
#[hegel::test]
fn hash_is_self_equal(tc: TestCase) {
    let files = draw_files(&tc);
    let dir = tempdir().expect("tempdir");
    materialize(dir.path(), &files);

    let h1 = hash_working_tree(dir.path(), &[]).expect("h1");
    let h2 = hash_working_tree(dir.path(), &[]).expect("h2");

    assert_eq!(h1, h2, "hash of same tree diverged across two reads");
}

// ----------------------------------------------------------------------------
// Property 2 — Equivalence under on-disk creation order.
//
// Two trees with identical (path, mode, content) tuples produce
// equal hashes regardless of the order their files were created
// on disk. This is the *cross-runner* determinism property —
// runner A might fetch a tarball, runner B might `git checkout`,
// and the on-disk inode order will differ; the canonical hash
// must not.
// ----------------------------------------------------------------------------
#[hegel::test]
fn hash_is_order_independent(tc: TestCase) {
    let files = draw_files(&tc);
    if files.is_empty() {
        return;
    }

    let dir_a = tempdir().expect("tempdir A");
    let dir_b = tempdir().expect("tempdir B");

    materialize(dir_a.path(), &files);

    let mut reversed = files.clone();
    reversed.reverse();
    materialize(dir_b.path(), &reversed);

    let h_a = hash_working_tree(dir_a.path(), &[]).expect("hash A");
    let h_b = hash_working_tree(dir_b.path(), &[]).expect("hash B");

    assert_eq!(
        h_a, h_b,
        "hash differed for trees with same content but different creation order"
    );
}

// ----------------------------------------------------------------------------
// Property 3 — Content sensitivity.
//
// Changing one byte of any file's content changes the hash. This
// is the standard collision-resistance handoff to SHA-256: if the
// canonical encoding loses content information, this property
// falsifies.
// ----------------------------------------------------------------------------
#[hegel::test]
fn hash_changes_on_content_mutation(tc: TestCase) {
    let mut files = draw_files(&tc);
    if files.is_empty() {
        return;
    }
    let target = tc.draw(
        generators::integers::<usize>()
            .min_value(0)
            .max_value(files.len() - 1),
    );

    let dir_a = tempdir().expect("tempdir A");
    let dir_b = tempdir().expect("tempdir B");

    materialize(dir_a.path(), &files);
    let h_a = hash_working_tree(dir_a.path(), &[]).expect("hash A");

    // Mutate: append a byte. Append (vs flip) keeps the file
    // length distinct from its baseline — the SHA-256 of the
    // mutated content is unequal regardless of what byte we pick.
    files[target].content.push(0xff);
    materialize(dir_b.path(), &files);
    let h_b = hash_working_tree(dir_b.path(), &[]).expect("hash B");

    assert_ne!(
        h_a, h_b,
        "content mutation didn't change hash (file: {})",
        files[target].rel_path
    );
}

// ----------------------------------------------------------------------------
// Property 4 — Path-set sensitivity.
//
// Adding a new file changes the hash. A subset of the tree must
// hash differently from the full tree.
// ----------------------------------------------------------------------------
#[hegel::test]
fn hash_changes_on_file_addition(tc: TestCase) {
    let files = draw_files(&tc);
    if files.is_empty() {
        return;
    }

    let dir_a = tempdir().expect("tempdir A");
    let dir_b = tempdir().expect("tempdir B");

    materialize(dir_a.path(), &files);
    let h_a = hash_working_tree(dir_a.path(), &[]).expect("hash A");

    // Inject one extra file at a fresh path.
    let mut augmented = files.clone();
    augmented.push(DrawnFile {
        rel_path: "__source_fetch_test_extra__/sentinel.bin".to_string(),
        content: b"sentinel".to_vec(),
        executable: false,
    });
    materialize(dir_b.path(), &augmented);
    let h_b = hash_working_tree(dir_b.path(), &[]).expect("hash B");

    assert_ne!(h_a, h_b, "adding a file didn't change hash");
}

// ----------------------------------------------------------------------------
// Property 5 — Exclude-dirs respected.
//
// Files inside an excluded directory don't contribute to the hash.
// `.git` is the canonical exclusion target — two clones that
// differ only in their `.git` packing must produce equal
// `tree_hash`.
// ----------------------------------------------------------------------------
#[hegel::test]
fn excluded_dirs_dont_contribute(tc: TestCase) {
    let files = draw_files(&tc);
    let dir_a = tempdir().expect("tempdir A");
    let dir_b = tempdir().expect("tempdir B");

    materialize(dir_a.path(), &files);
    materialize(dir_b.path(), &files);

    // Inject random content into `.git/` of dir_b only. With
    // `exclude_dirs=&[".git"]` the hashes must still agree.
    let git_a: PathBuf = dir_a.path().join(".git");
    let git_b: PathBuf = dir_b.path().join(".git");
    fs::create_dir_all(&git_a).expect("mkdir .git A");
    fs::create_dir_all(&git_b).expect("mkdir .git B");
    File::create(git_a.join("HEAD"))
        .expect("create HEAD A")
        .write_all(b"ref: refs/heads/main")
        .expect("write A");
    File::create(git_b.join("HEAD"))
        .expect("create HEAD B")
        .write_all(b"ref: refs/heads/totally-different")
        .expect("write B");
    let n = tc.draw(generators::integers::<usize>().min_value(1).max_value(3));
    for i in 0..n {
        File::create(git_b.join(format!("packed-refs-{i}")))
            .expect("create extra B")
            .write_all(b"differs")
            .expect("write extra B");
    }

    let h_a = hash_working_tree(dir_a.path(), &[".git"]).expect("hash A");
    let h_b = hash_working_tree(dir_b.path(), &[".git"]).expect("hash B");

    assert_eq!(h_a, h_b, ".git contents leaked into tree hash");
}

// ----------------------------------------------------------------------------
// Property 6 — output_hash binds resolved_sha.
//
// Two `SourceFetchOutput` values with equal `tree_hash` but
// different `resolved_sha` produce different `output_hash`. This
// is what makes branch-moves-mid-round detectable: even if the
// trees coincidentally agree, the SHAs surface the divergence.
// ----------------------------------------------------------------------------
#[hegel::test]
fn output_hash_binds_resolved_sha(tc: TestCase) {
    let tree_bytes: Vec<u8> = tc.draw(generators::binary().min_size(32).max_size(32));
    let mut tree: [u8; 32] = [0; 32];
    tree.copy_from_slice(&tree_bytes);

    let sha_a: String = format!("{:040x}", tc.draw(generators::integers::<u128>()));
    let sha_b: String = format!("{:040x}", tc.draw(generators::integers::<u128>()));
    if sha_a == sha_b {
        return;
    }

    let h_a = output_hash(&SourceFetchOutput {
        resolved_sha: sha_a,
        tree_hash: tree,
    });
    let h_b = output_hash(&SourceFetchOutput {
        resolved_sha: sha_b,
        tree_hash: tree,
    });

    assert_ne!(
        h_a, h_b,
        "output_hash didn't bind resolved_sha — branch divergence undetectable"
    );
}

// ----------------------------------------------------------------------------
// Smoke — empty directory is a defined hash (not all-zero, not panic).
// ----------------------------------------------------------------------------
#[test]
fn empty_dir_has_defined_hash() {
    let dir = tempdir().expect("tempdir");
    let h = hash_working_tree(dir.path(), &[]).expect("hash empty");
    // Empty Sha256 is a known constant; we just need it to not be
    // an all-zero return-on-failure.
    let zero: [u8; 32] = [0; 32];
    assert_ne!(h, zero, "empty-dir hash collapsed to all-zero");
}
