//! Property-based tests for `cosaci::verifier`.
//!
//! Encodes the falsifiable claims of `hypotheses/det-exec-verifier.md`
//! (SPEC.md §6.1a, class A). The *runner* determinism sub-claim (same env
//! → same output bytes on a real WASM/Firecracker/Docker runtime) is
//! class C and lives in `hypotheses/real-runtime-determinism.md`. Here we
//! only prove the verifier's pure Merkle algebra.

use std::collections::HashSet;

use cosaci::verifier::{compute_root, inclusion_proof, verify_inclusion, LeafHash};
use hegel::{generators, TestCase};

// ----------------------------------------------------------------------------
// Draw helpers
// ----------------------------------------------------------------------------

fn draw_leaf(tc: &TestCase) -> LeafHash {
    let v: Vec<u8> = tc.draw(generators::binary().min_size(32).max_size(32));
    let mut arr = [0_u8; 32];
    arr.copy_from_slice(&v);
    arr
}

/// Draw a set of *distinct* leaves of size n ∈ [min, max].
fn draw_unique_leaves(tc: &TestCase, min: usize, max: usize) -> Vec<LeafHash> {
    let n = tc.draw(
        generators::integers::<usize>()
            .min_value(min)
            .max_value(max),
    );
    let mut seen = HashSet::new();
    let mut leaves = Vec::with_capacity(n);
    // Draw-and-retry pattern with a small bound (we want unique 32-byte
    // hashes; Hegel won't collide much for random bytes).
    let mut attempts = 0;
    while leaves.len() < n && attempts < n * 4 {
        let leaf = draw_leaf(tc);
        if seen.insert(leaf) {
            leaves.push(leaf);
        }
        attempts += 1;
    }
    leaves
}

// ----------------------------------------------------------------------------
// Property 1 — empty set returns the specified sentinel (None).
// ----------------------------------------------------------------------------
#[hegel::test]
fn empty_set_root_is_none(_tc: hegel::TestCase) {
    assert_eq!(compute_root(&[]), None);
}

// ----------------------------------------------------------------------------
// Property 2 — root determinism.
// Same leaf set → same root, across repeated calls (no ambient state).
// ----------------------------------------------------------------------------
#[hegel::test]
fn root_is_deterministic(tc: hegel::TestCase) {
    let leaves = draw_unique_leaves(&tc, 1, 16);
    let r1 = compute_root(&leaves);
    let r2 = compute_root(&leaves);
    assert_eq!(r1, r2, "root was not deterministic across calls");
}

// ----------------------------------------------------------------------------
// Property 3 — order-insensitivity under canonical sort.
// Permuting the input slice yields the same root.
// ----------------------------------------------------------------------------
#[hegel::test]
fn root_is_order_insensitive(tc: hegel::TestCase) {
    let leaves = draw_unique_leaves(&tc, 1, 16);
    let baseline = compute_root(&leaves);

    if leaves.len() <= 1 {
        return; // nothing to permute
    }
    let perm: Vec<usize> = tc.draw(
        generators::vecs(
            generators::integers::<usize>()
                .min_value(0)
                .max_value(leaves.len() - 1),
        )
        .unique(true)
        .min_size(leaves.len())
        .max_size(leaves.len()),
    );
    let permuted: Vec<LeafHash> = perm.iter().map(|&i| leaves[i]).collect();
    let shuffled = compute_root(&permuted);
    assert_eq!(baseline, shuffled, "permutation changed the Merkle root");
}

// ----------------------------------------------------------------------------
// Property 4 — inclusion-proof soundness.
// For any leaf in the set, the generated proof verifies against the root.
// ----------------------------------------------------------------------------
#[hegel::test]
fn inclusion_proof_verifies(tc: hegel::TestCase) {
    let leaves = draw_unique_leaves(&tc, 1, 16);
    let root = compute_root(&leaves).expect("nonempty leaves must have a root");

    let pick = tc.draw(
        generators::integers::<usize>()
            .min_value(0)
            .max_value(leaves.len() - 1),
    );
    let leaf = leaves[pick];
    let proof = inclusion_proof(&leaves, leaf).expect("leaf is in the set");
    assert!(
        verify_inclusion(&proof, root),
        "valid inclusion proof failed to verify"
    );
}

// ----------------------------------------------------------------------------
// Property 5 — inclusion-proof non-forgeability.
// A leaf not in the set has no inclusion proof; additionally, verifying a
// genuine proof against a different (non-member) leaf must fail.
// ----------------------------------------------------------------------------
#[hegel::test]
fn non_member_cannot_forge_inclusion(tc: hegel::TestCase) {
    let leaves = draw_unique_leaves(&tc, 1, 16);
    let root = compute_root(&leaves).expect("nonempty leaves must have a root");
    let member_set: HashSet<LeafHash> = leaves.iter().copied().collect();

    let candidate = draw_leaf(&tc);
    if member_set.contains(&candidate) {
        return; // skip: Hegel hit a genuine member
    }

    // No proof should exist for a non-member.
    assert!(
        inclusion_proof(&leaves, candidate).is_none(),
        "inclusion_proof produced a proof for a non-member"
    );

    // Substituting the non-member into a genuine proof must fail verification.
    let pick = tc.draw(
        generators::integers::<usize>()
            .min_value(0)
            .max_value(leaves.len() - 1),
    );
    let mut proof = inclusion_proof(&leaves, leaves[pick]).expect("member has a proof");
    proof.leaf = candidate;
    assert!(
        !verify_inclusion(&proof, root),
        "verifier accepted a non-member substituted into a genuine proof"
    );
}

// ----------------------------------------------------------------------------
// Property 6 — proof-hash mutation rejects.
// Flipping any bit in the proof hashes must cause verification to fail
// (with overwhelming probability — SHA-256 second-preimage resistance).
// ----------------------------------------------------------------------------
#[hegel::test]
fn proof_hash_mutation_rejects(tc: hegel::TestCase) {
    // Need at least 2 leaves so a non-empty proof exists.
    let leaves = draw_unique_leaves(&tc, 2, 16);
    let root = compute_root(&leaves).expect("nonempty leaves must have a root");

    let pick = tc.draw(
        generators::integers::<usize>()
            .min_value(0)
            .max_value(leaves.len() - 1),
    );
    let mut proof = inclusion_proof(&leaves, leaves[pick]).expect("member has a proof");
    if proof.proof_hashes.is_empty() {
        return; // tree of size 1 has an empty proof, skip
    }

    let hash_idx = tc.draw(
        generators::integers::<usize>()
            .min_value(0)
            .max_value(proof.proof_hashes.len() - 1),
    );
    let byte_idx = tc.draw(generators::integers::<usize>().min_value(0).max_value(31));
    let bit_idx = tc.draw(generators::integers::<u8>().min_value(0).max_value(7));
    proof.proof_hashes[hash_idx][byte_idx] ^= 1_u8 << bit_idx;

    assert!(
        !verify_inclusion(&proof, root),
        "verifier accepted a proof with a mutated hash"
    );
}
