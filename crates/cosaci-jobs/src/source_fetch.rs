//! Source-fetching step (issue #40) — deterministic git checkout.
//!
//! Real CI starts by fetching code at a specific ref. Without a
//! deterministic, content-addressed source-fetch primitive every
//! committee member is fetching independently and there's no way
//! to assert "we all checked out the same tree."
//!
//! # Layered design
//!
//! - [`hash_working_tree`] — pure file-system primitive. Walks a
//!   directory, emits canonical `(rel_path, mode, blob_sha256)`
//!   records, and hashes the lexicographically-sorted record
//!   stream. Network-free; this is the falsifiable core under
//!   `hypotheses/source-fetch-determinism.md`.
//! - [`execute_source_fetch`] — thin wrapper that shells out to
//!   `git`, clones into a tempdir, checks out `reference`, runs
//!   `git rev-parse HEAD` to capture the resolved SHA, then calls
//!   `hash_working_tree` over the working tree.
//!
//! The resolved SHA is part of the step's output hash, so two
//! runners that resolved a moving branch to different commits
//! produce different `output_hash`es — committee disagreement
//! surfaces at the quorum layer (issue #40 acceptance criterion
//! "branch-moves-mid-round detection").

use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Successful outcome of [`execute_source_fetch`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceFetchOutput {
    /// Lowercase-hex-encoded 40-char commit SHA the checkout
    /// resolved to. For commit-SHA refs this is the input
    /// reference; for branch/tag refs this is what HEAD pointed
    /// to at fetch time.
    pub resolved_sha: String,
    /// SHA-256 of the canonical tree listing. Equal across
    /// runners iff the working trees are equivalent in
    /// (path, mode, content).
    pub tree_hash: [u8; 32],
}

/// Errors the source-fetch executor can return.
#[derive(Debug)]
pub enum SourceFetchError {
    /// `git` is not on `PATH`.
    GitNotFound,
    /// `git clone` failed. Carries stderr.
    CloneFailed(String),
    /// `git checkout <ref>` failed. Carries stderr.
    CheckoutFailed(String),
    /// `git rev-parse HEAD` failed. Carries stderr.
    ResolveFailed(String),
    /// Generic I/O error walking the tree or creating the tempdir.
    Io(io::Error),
}

impl std::fmt::Display for SourceFetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GitNotFound => write!(f, "git not on PATH"),
            Self::CloneFailed(s) => write!(f, "git clone failed: {s}"),
            Self::CheckoutFailed(s) => write!(f, "git checkout failed: {s}"),
            Self::ResolveFailed(s) => write!(f, "git rev-parse failed: {s}"),
            Self::Io(e) => write!(f, "io: {e}"),
        }
    }
}

impl std::error::Error for SourceFetchError {}

impl From<io::Error> for SourceFetchError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Walk `root` recursively and return SHA-256 of the canonical
/// tree listing. Two equivalent trees produce equal hashes; any
/// single-bit divergence in path, file mode, or file content
/// propagates.
///
/// `exclude_dirs` is matched against directory *names* (not full
/// paths) — the typical use is `&[".git"]` to skip the metadata
/// directory after a clone.
///
/// # Determinism guarantees
///
/// - **Path normalization**: paths are stored relative to `root`
///   with `/` separators on every platform; on-disk traversal
///   order is irrelevant because the records are sorted before
///   hashing.
/// - **Mode canonicalization**: file modes are reduced to git's
///   two-mode model — `0o100644` (regular) or `0o100755`
///   (executable, on Unix when any execute bit is set). On
///   non-Unix the mode is always `0o100644`. This matches what
///   `git ls-tree` emits, so `tree_hash` agrees with what an
///   external `git`-aware verifier would compute.
/// - **Symlinks are skipped**, not followed and not recorded.
///   Symlinks are a determinism hazard (target may be absolute,
///   may dangle, may follow `/proc`) and v0.3 doesn't need them.
///
/// # Errors
///
/// Returns the first I/O error encountered while walking. A
/// missing `root` returns `ErrorKind::NotFound`.
pub fn hash_working_tree(root: &Path, exclude_dirs: &[&str]) -> io::Result<[u8; 32]> {
    let mut entries: Vec<(String, u32, [u8; 32])> = Vec::new();
    walk(root, root, exclude_dirs, &mut entries)?;
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut h = Sha256::new();
    for (path, mode, blob_sha) in &entries {
        // Length-prefix the path so "ab" + "c" can't collide with
        // "a" + "bc" — a classic canonicalization trap.
        let path_bytes = path.as_bytes();
        h.update((path_bytes.len() as u64).to_le_bytes());
        h.update(path_bytes);
        h.update(mode.to_le_bytes());
        h.update(blob_sha);
    }
    Ok(h.finalize().into())
}

fn walk(
    root: &Path,
    dir: &Path,
    exclude_dirs: &[&str],
    out: &mut Vec<(String, u32, [u8; 32])>,
) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        let path = entry.path();
        let name_os = entry.file_name();
        let name = name_os.to_string_lossy();

        if ft.is_dir() {
            if exclude_dirs.iter().any(|e| *e == name.as_ref()) {
                continue;
            }
            walk(root, &path, exclude_dirs, out)?;
        } else if ft.is_file() {
            let rel = path
                .strip_prefix(root)
                .expect("walk descended from root")
                .to_path_buf();
            let rel_str = path_to_unix(&rel);
            let meta = entry.metadata()?;
            let mode = canonical_mode(&meta);
            let blob_sha = hash_file(&path)?;
            out.push((rel_str, mode, blob_sha));
        }
        // Symlinks (ft.is_symlink()) intentionally skipped.
    }
    Ok(())
}

fn path_to_unix(p: &Path) -> String {
    p.components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn hash_file(path: &Path) -> io::Result<[u8; 32]> {
    let mut h = Sha256::new();
    let mut buf = [0_u8; 8192];
    let mut f = File::open(path)?;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().into())
}

#[cfg(unix)]
fn canonical_mode(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    let perms = meta.mode() & 0o777;
    if perms & 0o111 != 0 {
        0o100_755
    } else {
        0o100_644
    }
}

#[cfg(not(unix))]
fn canonical_mode(_meta: &std::fs::Metadata) -> u32 {
    0o100_644
}

/// Run `git clone <url> .` into a fresh temporary directory,
/// `git checkout <reference>`, capture the resolved SHA, and
/// hash the resulting working tree.
///
/// The tempdir is cleaned up when the returned `SourceFetchOutput`
/// is dropped — but [`execute_source_fetch`] returns only the
/// hashes, not the working tree itself. v0.3 captures source
/// state into the attestation; subsequent steps that need the
/// checkout on disk are out of scope until the multi-step
/// pipeline plumbing lands.
///
/// # Errors
///
/// Returns [`SourceFetchError`] for any failure of the underlying
/// git invocations or tree walk. `git` not being on `PATH` is
/// reported as [`SourceFetchError::GitNotFound`].
pub fn execute_source_fetch(
    url: &str,
    reference: &str,
) -> Result<SourceFetchOutput, SourceFetchError> {
    let temp = tempfile::tempdir()?;
    let workdir: PathBuf = temp.path().to_path_buf();

    run_git(&workdir, &["clone", url, "."])
        .map_err(|e| classify(e, SourceFetchError::CloneFailed))?;
    run_git(&workdir, &["checkout", reference])
        .map_err(|e| classify(e, SourceFetchError::CheckoutFailed))?;
    let head = run_git(&workdir, &["rev-parse", "HEAD"])
        .map_err(|e| classify(e, SourceFetchError::ResolveFailed))?;
    let resolved_sha = head.trim().to_string();

    let tree_hash = hash_working_tree(&workdir, &[".git"])?;
    Ok(SourceFetchOutput {
        resolved_sha,
        tree_hash,
    })
}

enum GitInvocationError {
    NotFound,
    Io(io::Error),
    NonZero(String),
}

fn run_git(cwd: &Path, args: &[&str]) -> Result<String, GitInvocationError> {
    let out = Command::new("git").args(args).current_dir(cwd).output();
    let out = match out {
        Ok(o) => o,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(GitInvocationError::NotFound),
        Err(e) => return Err(GitInvocationError::Io(e)),
    };
    if !out.status.success() {
        return Err(GitInvocationError::NonZero(
            String::from_utf8_lossy(&out.stderr).into_owned(),
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn classify(e: GitInvocationError, nonzero: fn(String) -> SourceFetchError) -> SourceFetchError {
    match e {
        GitInvocationError::NotFound => SourceFetchError::GitNotFound,
        GitInvocationError::Io(e) => SourceFetchError::Io(e),
        GitInvocationError::NonZero(s) => nonzero(s),
    }
}

/// Canonical `output_hash` for a `Step::SourceFetch` step (issue
/// #40). Binds both the resolved SHA and the tree hash so a
/// committee member that resolved a moving branch to a different
/// commit produces a divergent value even if (by coincidence) the
/// tree happened to look the same.
#[must_use]
pub fn output_hash(out: &SourceFetchOutput) -> [u8; 32] {
    let mut h = Sha256::new();
    let sha_bytes = out.resolved_sha.as_bytes();
    h.update((sha_bytes.len() as u64).to_le_bytes());
    h.update(sha_bytes);
    h.update(out.tree_hash);
    h.finalize().into()
}
