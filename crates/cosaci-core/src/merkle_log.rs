//! Append-only Merkle log for attestation anchoring.
//!
//! Source: `SPEC.md` §10.2 / `hypotheses/merkle-log-append-only.md`
//! (class A) + `hypotheses/merkle-log-persistence.md` (issue #33,
//! class A). The log is append-only; the Merkle root at any prefix
//! length is a pure function of that prefix; inclusion proofs against
//! a frozen prefix-root remain valid regardless of later appends.
//!
//! The core log uses `rs_merkle`'s binary Merkle tree over the prefix
//! of entries. Additionally, this module exposes **MMR peak decomposition**
//! (`peak_heights`, `peak_hashes`) — given a log length `n`, the MMR
//! peaks are exactly the perfect-binary-subtrees spanning the leaves,
//! one per 1-bit in the binary representation of `n`. The key property:
//! **once a peak is formed (the log grows past `start + 2^h`), that
//! peak's hash never changes** — this is the structural guarantee that
//! a production MMR implementation would use to achieve O(log n) proof
//! extraction via peak caching.
//!
//! # Persistence (issue #33)
//!
//! `MerkleLog` is generic over a [`Store`] backend. Two impls ship:
//!
//! - [`MemStore`] (default) — `Vec<Hash>` in RAM. Identical to the v0.2
//!   behavior; `MerkleLog::new()` constructs this. Restart loses state.
//! - [`FileStore`] — append-only file with one fixed-size 32-byte record
//!   per entry. `sync_data` after every append; reopening from the same
//!   path recovers byte-identical state. Construct via
//!   `MerkleLog::<FileStore>::open(path)`.
//!
//! The in-memory `entries: Vec<Hash>` cache mirrors the store, so
//! `root` / `inclusion_proof` / `peak_hashes` are O(n) on the cache —
//! same performance as v0.2. The store is the durable mirror.

use std::convert::Infallible;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use rs_merkle::{Hasher, MerkleProof, MerkleTree, algorithms::Sha256};
use serde::{Deserialize, Serialize};

/// Leaf / entry hash.
pub type Hash = [u8; 32];

/// Hash arbitrary bytes into a log entry.
#[must_use]
pub fn hash_bytes(data: &[u8]) -> Hash {
    Sha256::hash(data)
}

/// Inclusion proof bundle. Wire-shippable so the read API (issue #44)
/// can hand it to external auditors.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionProof {
    /// 0-indexed position of the entry in the log.
    pub position: u64,
    /// The leaf (entry) hash that this proof attests to.
    pub entry: Hash,
    /// Sibling hashes along the path from leaf to root.
    pub proof_hashes: Vec<Hash>,
    /// Total entry count at the time the proof was issued.
    pub length_at_proof: u64,
}

// ────────────────────────────────────────────────────────────────────────
// Store trait + impls (issue #33)
// ────────────────────────────────────────────────────────────────────────

/// Pluggable durable backend for [`MerkleLog`]. Two impls ship:
/// [`MemStore`] for tests + the in-process demo, [`FileStore`] for
/// production.
///
/// Implementations of [`append`](Store::append) MUST be durable when
/// they return `Ok` — the calling code treats a successful return as a
/// commit. For [`FileStore`] this means `sync_data` before returning;
/// for [`MemStore`] there's no disk to sync, but the API contract is
/// the same.
pub trait Store {
    /// Error type — `Infallible` for in-memory backends,
    /// `std::io::Error` for disk-backed ones.
    type Error;

    /// Append `entry` and return its 0-indexed position. Must be
    /// durable on `Ok` (see trait docs).
    ///
    /// # Errors
    ///
    /// Implementation-defined.
    fn append(&mut self, entry: Hash) -> Result<u64, Self::Error>;

    /// Read every entry from the backing store, in append order.
    /// Called once at log open to populate the in-memory mirror.
    ///
    /// # Errors
    ///
    /// Implementation-defined.
    fn read_all(&self) -> Result<Vec<Hash>, Self::Error>;
}

/// In-memory store. The default backend; never fails.
#[derive(Clone, Debug, Default)]
pub struct MemStore {
    entries: Vec<Hash>,
}

impl Store for MemStore {
    type Error = Infallible;

    fn append(&mut self, entry: Hash) -> Result<u64, Self::Error> {
        let pos = self.entries.len() as u64;
        self.entries.push(entry);
        Ok(pos)
    }

    fn read_all(&self) -> Result<Vec<Hash>, Self::Error> {
        Ok(self.entries.clone())
    }
}

/// Append-only file-backed store. Each entry is a fixed 32-byte record;
/// the file is a pure concatenation of `Hash` values, no header or
/// checksum. `sync_data` is called after every append before returning,
/// so a successful `Ok(_)` means the entry is on disk.
///
/// Reopening from the same path recovers the log byte-for-byte. The
/// hypothesis card `merkle-log-persistence` encodes this as a Hegel
/// property.
pub struct FileStore {
    path: PathBuf,
    file: File,
    len: u64,
}

impl FileStore {
    /// Open (or create) a file-backed log at `path`. The file is
    /// expected to be a multiple of 32 bytes; a non-multiple length
    /// indicates corruption and returns `InvalidData`.
    ///
    /// # Errors
    ///
    /// I/O errors from opening the file, or `InvalidData` if the
    /// existing file size isn't a multiple of 32.
    pub fn open<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)?;
        let bytes = file.metadata()?.len();
        if bytes % 32 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "log file size {bytes} is not a multiple of 32 — file corrupt or truncated mid-append"
                ),
            ));
        }
        Ok(Self {
            path,
            file,
            len: bytes / 32,
        })
    }
}

impl Store for FileStore {
    type Error = std::io::Error;

    fn append(&mut self, entry: Hash) -> std::io::Result<u64> {
        self.file.write_all(&entry)?;
        self.file.sync_data()?;
        let pos = self.len;
        self.len += 1;
        Ok(pos)
    }

    fn read_all(&self) -> std::io::Result<Vec<Hash>> {
        let mut f = OpenOptions::new().read(true).open(&self.path)?;
        let mut buf = Vec::with_capacity((self.len * 32) as usize);
        f.read_to_end(&mut buf)?;
        if buf.len() % 32 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "log file read length is not a multiple of 32",
            ));
        }
        let mut entries = Vec::with_capacity(buf.len() / 32);
        for chunk in buf.chunks_exact(32) {
            let mut h = [0_u8; 32];
            h.copy_from_slice(chunk);
            entries.push(h);
        }
        Ok(entries)
    }
}

// ────────────────────────────────────────────────────────────────────────
// MerkleLog
// ────────────────────────────────────────────────────────────────────────

/// Append-only Merkle log. Generic over the [`Store`] backend; defaults
/// to [`MemStore`] for backward compatibility with the v0.2 in-memory
/// API. The in-memory `entries` cache mirrors the store so root +
/// inclusion-proof computation are O(n) on RAM, not on disk.
#[derive(Debug)]
pub struct MerkleLog<S = MemStore> {
    entries: Vec<Hash>,
    store: S,
}

impl Default for MerkleLog<MemStore> {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleLog<MemStore> {
    /// Construct an in-memory log. v0.2 API.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            store: MemStore::default(),
        }
    }

    /// Append an entry. Returns its position (0-indexed). Infallible
    /// for the in-memory backend; preserves the v0.2 API.
    pub fn append(&mut self, entry: Hash) -> u64 {
        let pos = self
            .store
            .append(entry)
            .unwrap_or_else(|never| match never {});
        self.entries.push(entry);
        pos
    }
}

impl MerkleLog<FileStore> {
    /// Open a file-backed log at `path`. The file is created if it
    /// doesn't exist; if it exists, every previously-appended entry
    /// is loaded into the in-memory mirror.
    ///
    /// # Errors
    ///
    /// I/O errors from opening or reading the file, or `InvalidData`
    /// if the file is corrupt (size not a multiple of 32).
    pub fn open<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let store = FileStore::open(path)?;
        let entries = store.read_all()?;
        Ok(Self { entries, store })
    }

    /// Append an entry. Fails if the underlying disk write or fsync
    /// fails. On `Ok`, the entry is durable.
    ///
    /// # Errors
    ///
    /// I/O errors from `write_all` or `sync_data`.
    pub fn append(&mut self, entry: Hash) -> std::io::Result<u64> {
        let pos = self.store.append(entry)?;
        self.entries.push(entry);
        Ok(pos)
    }
}

// Read-side methods are independent of the store; they operate on the
// in-memory mirror.
impl<S> MerkleLog<S> {
    /// Total number of entries appended.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.entries.len() as u64
    }

    /// Whether the log holds zero entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Entry at `position`, or `None` if out of range.
    #[must_use]
    pub fn entry_at(&self, position: u64) -> Option<Hash> {
        self.entries.get(position as usize).copied()
    }

    /// Root over the entire current log. `None` if the log is empty.
    #[must_use]
    pub fn root(&self) -> Option<Hash> {
        if self.entries.is_empty() {
            return None;
        }
        MerkleTree::<Sha256>::from_leaves(&self.entries).root()
    }

    /// Root over the first `n` entries. `None` for `n == 0` or `n > len`.
    /// This is the "anchored root" that frozen bulletin entries would
    /// reference; it is a pure function of the first `n` entries and does
    /// not change as more entries are appended beyond position `n`.
    #[must_use]
    pub fn root_at(&self, n: u64) -> Option<Hash> {
        if n == 0 || n > self.entries.len() as u64 {
            return None;
        }
        MerkleTree::<Sha256>::from_leaves(&self.entries[..n as usize]).root()
    }

    /// Inclusion proof for the entry at `position`, against the root over
    /// the first `length` entries. Requires `position < length <= len()`.
    #[must_use]
    pub fn inclusion_proof_at(&self, position: u64, length: u64) -> Option<InclusionProof> {
        if length == 0 || length > self.len() || position >= length {
            return None;
        }
        let slice = &self.entries[..length as usize];
        let tree = MerkleTree::<Sha256>::from_leaves(slice);
        let proof = tree.proof(&[position as usize]);
        Some(InclusionProof {
            position,
            entry: slice[position as usize],
            proof_hashes: proof.proof_hashes().to_vec(),
            length_at_proof: length,
        })
    }

    /// Inclusion proof against the current root.
    #[must_use]
    pub fn inclusion_proof(&self, position: u64) -> Option<InclusionProof> {
        self.inclusion_proof_at(position, self.len())
    }

    /// MMR peak decomposition of the first `length` leaves.
    ///
    /// For a log of `length` leaves, the MMR has one peak per 1-bit in
    /// the binary representation of `length`. Peaks are returned in
    /// descending-height order (largest peak first, matching MSB-to-LSB
    /// bit order). Each peak at height `h` covers `2^h` consecutive
    /// leaves, starting immediately after the previous peak.
    ///
    /// Returns an empty vector for `length == 0` or `length > len()`.
    ///
    /// This is the structural decomposition a production MMR would
    /// cache; we compute it on demand from the leaf slice.
    #[must_use]
    pub fn peak_hashes(&self, length: u64) -> Vec<Hash> {
        if length == 0 || length > self.len() {
            return Vec::new();
        }
        let mut peaks = Vec::new();
        let mut start: usize = 0;
        for h in peak_heights(length) {
            let count = 1_usize << h;
            let slice = &self.entries[start..start + count];
            let root = MerkleTree::<Sha256>::from_leaves(slice)
                .root()
                .expect("peak over 2^h leaves is well-defined");
            peaks.push(root);
            start += count;
        }
        peaks
    }
}

/// Peak heights of an MMR with `length` leaves, in descending order
/// (MSB-to-LSB bit decomposition of `length`). For `length == 11`
/// (binary `1011`), returns `[3, 1, 0]` — peaks covering 8, 2, and 1
/// leaves respectively.
#[must_use]
pub fn peak_heights(length: u64) -> Vec<u8> {
    let mut out = Vec::new();
    for h in (0..64).rev() {
        if (length >> h) & 1 == 1 {
            out.push(h as u8);
        }
    }
    out
}

/// Verify an inclusion proof against a root. The `root` must correspond
/// to the same `length_at_proof` that generated the proof.
#[must_use]
pub fn verify_inclusion(proof: &InclusionProof, root: Hash) -> bool {
    let mp = MerkleProof::<Sha256>::new(proof.proof_hashes.clone());
    mp.verify(
        root,
        &[proof.position as usize],
        &[proof.entry],
        proof.length_at_proof as usize,
    )
}
