//! Append-only Merkle log for attestation anchoring.
//!
//! Source: `SPEC.md` §10.2 / `hypotheses/merkle-log-append-only.md`
//! (class A). The log is append-only; the Merkle root at any prefix
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

use rs_merkle::{Hasher, MerkleProof, MerkleTree, algorithms::Sha256};

/// Leaf / entry hash.
pub type Hash = [u8; 32];

/// Hash arbitrary bytes into a log entry.
#[must_use]
pub fn hash_bytes(data: &[u8]) -> Hash {
    Sha256::hash(data)
}

/// Inclusion proof bundle.
#[derive(Clone, Debug)]
pub struct InclusionProof {
    pub position: u64,
    pub entry: Hash,
    pub proof_hashes: Vec<Hash>,
    pub length_at_proof: u64,
}

/// Append-only Merkle log. Only `append` mutates state; there is no
/// deletion, overwrite, or reordering API. Past roots and past proofs
/// are not cached — they are recomputed from the authoritative entry
/// list on demand.
#[derive(Clone, Debug, Default)]
pub struct MerkleLog {
    entries: Vec<Hash>,
}

impl MerkleLog {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an entry. Returns its position (0-indexed).
    pub fn append(&mut self, entry: Hash) -> u64 {
        let pos = self.entries.len() as u64;
        self.entries.push(entry);
        pos
    }

    #[must_use]
    pub fn len(&self) -> u64 {
        self.entries.len() as u64
    }

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
