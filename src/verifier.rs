//! Deterministic-execution verifier: Merkle algebra over leaf hashes.
//!
//! Source: `SPEC.md` §6.1a / `hypotheses/det-exec-verifier.md` (class A).
//! Combines `(env_hash, cmd_hash, output_hash, artifact_hashes…)` into a
//! canonical Merkle root. Canonicalization is **leaf sorting** before tree
//! construction so permuting input order yields the same root.
//!
//! Primitive commitment (2026-04-24): binary Merkle via `rs_merkle` 1.5
//! with SHA-256. The separate append-only log in `hypotheses/merkle-log-
//! append-only.md` (Tier 1) will use its own primitive (MMR) — the two
//! serve different workloads and can diverge.

use rs_merkle::{algorithms::Sha256, Hasher, MerkleProof, MerkleTree};

/// A 32-byte SHA-256 leaf hash. Opaque from the verifier's perspective —
/// callers decide what content to feed in (env hash, cmd hash, artifact
/// hash, etc.).
pub type LeafHash = [u8; 32];

/// Hash arbitrary bytes into a leaf. Convenience for callers that have raw
/// content rather than a pre-computed digest.
#[must_use]
pub fn hash_leaf(data: &[u8]) -> LeafHash {
    Sha256::hash(data)
}

/// Compute the canonical Merkle root over `leaves`.
///
/// Leaves are **sorted** before tree construction. Under canonical sort,
/// permuting the input slice yields the same root. Returns `None` for the
/// empty set (specified sentinel — not a panic, not a random value).
#[must_use]
pub fn compute_root(leaves: &[LeafHash]) -> Option<LeafHash> {
    if leaves.is_empty() {
        return None;
    }
    let mut sorted = leaves.to_vec();
    sorted.sort();
    MerkleTree::<Sha256>::from_leaves(&sorted).root()
}

/// A Merkle inclusion proof bundle: enough information for a verifier that
/// already knows the root to check whether a given leaf is in the set.
#[derive(Clone, Debug)]
pub struct InclusionProof {
    pub leaf: LeafHash,
    pub index: usize,
    pub proof_hashes: Vec<LeafHash>,
    pub total_leaves: usize,
}

/// Produce an inclusion proof for `leaf` against the Merkle tree over
/// `leaves` (sorted canonically). Returns `None` if `leaf` is not in
/// `leaves`, or if `leaves` is empty.
#[must_use]
pub fn inclusion_proof(leaves: &[LeafHash], leaf: LeafHash) -> Option<InclusionProof> {
    if leaves.is_empty() {
        return None;
    }
    let mut sorted = leaves.to_vec();
    sorted.sort();
    let index = sorted.iter().position(|&l| l == leaf)?;
    let tree = MerkleTree::<Sha256>::from_leaves(&sorted);
    let proof = tree.proof(&[index]);
    Some(InclusionProof {
        leaf,
        index,
        proof_hashes: proof.proof_hashes().to_vec(),
        total_leaves: sorted.len(),
    })
}

/// Verify that `proof` witnesses `leaf` in the Merkle set committed by
/// `root`. Returns true iff the proof reconstructs to `root`.
#[must_use]
pub fn verify_inclusion(proof: &InclusionProof, root: LeafHash) -> bool {
    let mp = MerkleProof::<Sha256>::new(proof.proof_hashes.clone());
    mp.verify(root, &[proof.index], &[proof.leaf], proof.total_leaves)
}
