//! Model-based test for `cosaci::merkle_log::MerkleLog`.
//!
//! Encodes the falsifiable claims of `hypotheses/merkle-log-append-only.md`
//! (SPEC.md §10.2, class A). The log is append-only; the Merkle root at
//! any prefix length is stable; inclusion proofs captured at an earlier
//! length verify against the root at that same length regardless of
//! later appends.

use std::collections::HashMap;

use cosaci::merkle_log::{verify_inclusion, Hash, InclusionProof, MerkleLog};
use hegel::{generators, TestCase};

// ----------------------------------------------------------------------------
// Draw helpers
// ----------------------------------------------------------------------------

fn draw_hash(tc: &TestCase) -> Hash {
    let v: Vec<u8> = tc.draw(generators::binary().min_size(32).max_size(32));
    let mut arr = [0_u8; 32];
    arr.copy_from_slice(&v);
    arr
}

struct LogTest {
    subject: MerkleLog,
    // Model: position → entry hash appended there.
    model: Vec<Hash>,
    // Frozen roots: length at which we took a snapshot → root bytes.
    frozen_roots: HashMap<u64, Hash>,
    // Frozen proofs: (position, length) → proof bundle + expected entry.
    frozen_proofs: Vec<InclusionProof>,
}

#[hegel::state_machine]
impl LogTest {
    // Append a new entry.
    #[rule]
    fn append(&mut self, tc: TestCase) {
        let entry = draw_hash(&tc);
        let pos = self.subject.append(entry);
        assert_eq!(pos, self.model.len() as u64, "position returned by append diverged");
        self.model.push(entry);
        assert_eq!(self.subject.len(), self.model.len() as u64);
    }

    // Freeze the current root at the current length. Later rules must
    // observe the same root at this length.
    #[rule]
    fn freeze_root(&mut self, _tc: TestCase) {
        let len = self.subject.len();
        if let Some(r) = self.subject.root_at(len) {
            self.frozen_roots.insert(len, r);
        }
    }

    // Generate and freeze an inclusion proof for an existing position.
    #[rule]
    fn freeze_proof(&mut self, tc: TestCase) {
        let len = self.subject.len();
        if len == 0 {
            return;
        }
        let position = tc.draw(
            generators::integers::<u64>()
                .min_value(0)
                .max_value(len - 1),
        );
        if let Some(proof) = self.subject.inclusion_proof_at(position, len) {
            self.frozen_proofs.push(proof);
        }
    }

    // Structural invariants — checked after every rule.
    #[invariant]
    fn entries_are_stable(&mut self, _: TestCase) {
        assert_eq!(self.subject.len(), self.model.len() as u64);
        for (i, &expected) in self.model.iter().enumerate() {
            let got = self.subject.entry_at(i as u64);
            assert_eq!(got, Some(expected), "entry diverged at position {}", i);
        }
    }

    // Frozen roots must remain equal to current root_at for the same length.
    #[invariant]
    fn frozen_roots_still_valid(&mut self, _: TestCase) {
        for (&len, &expected_root) in &self.frozen_roots.clone() {
            let current = self.subject.root_at(len);
            assert_eq!(
                current,
                Some(expected_root),
                "frozen root at length {} drifted: expected {:?}, got {:?}",
                len,
                expected_root,
                current
            );
        }
    }

    // Frozen proofs must still verify against the frozen root at their
    // length — appending never invalidates past proofs.
    #[invariant]
    fn frozen_proofs_still_verify(&mut self, _: TestCase) {
        for proof in &self.frozen_proofs.clone() {
            let root = self.subject.root_at(proof.length_at_proof).expect(
                "root_at must exist for a length that already had a proof issued",
            );
            assert!(
                verify_inclusion(proof, root),
                "frozen proof at position {} length {} no longer verifies",
                proof.position,
                proof.length_at_proof
            );
        }
    }
}

#[hegel::test]
fn log_preserves_past_entries_roots_and_proofs(tc: TestCase) {
    let test = LogTest {
        subject: MerkleLog::new(),
        model: Vec::new(),
        frozen_roots: HashMap::new(),
        frozen_proofs: Vec::new(),
    };
    hegel::stateful::run(test, tc);
}

// ----------------------------------------------------------------------------
// Additional pointwise properties (not inside the state machine).
// ----------------------------------------------------------------------------

// Empty log has no root.
#[hegel::test]
fn empty_log_root_is_none(_tc: hegel::TestCase) {
    let log = MerkleLog::new();
    assert_eq!(log.root(), None);
    assert!(log.is_empty());
    assert_eq!(log.len(), 0);
}

// Rewrite detection: two logs differing in any single entry produce
// different roots.
#[hegel::test]
fn mutation_in_any_position_changes_root(tc: hegel::TestCase) {
    let n = tc.draw(generators::integers::<usize>().min_value(1).max_value(16));
    let mut entries = Vec::with_capacity(n);
    for _ in 0..n {
        entries.push(draw_hash(&tc));
    }

    let mut log_a = MerkleLog::new();
    for &e in &entries {
        log_a.append(e);
    }
    let root_a = log_a.root().expect("nonempty");

    let mutate_pos = tc.draw(
        generators::integers::<usize>()
            .min_value(0)
            .max_value(n - 1),
    );
    let byte_idx = tc.draw(generators::integers::<usize>().min_value(0).max_value(31));
    let bit_idx = tc.draw(generators::integers::<u8>().min_value(0).max_value(7));
    let mut mutated = entries.clone();
    mutated[mutate_pos][byte_idx] ^= 1_u8 << bit_idx;

    if mutated == entries {
        return; // extremely unlikely (bit flip on already-zero?), skip
    }

    let mut log_b = MerkleLog::new();
    for &e in &mutated {
        log_b.append(e);
    }
    let root_b = log_b.root().expect("nonempty");

    assert_ne!(
        root_a, root_b,
        "mutated entry at pos {} did not change root",
        mutate_pos
    );
}

// Inclusion proofs generated at current length verify against the current
// root — the basic soundness of the proof function.
#[hegel::test]
fn current_proofs_verify(tc: hegel::TestCase) {
    let n = tc.draw(generators::integers::<usize>().min_value(1).max_value(16));
    let mut log = MerkleLog::new();
    for _ in 0..n {
        log.append(draw_hash(&tc));
    }
    let root = log.root().expect("nonempty");
    let position = tc.draw(
        generators::integers::<u64>()
            .min_value(0)
            .max_value((n - 1) as u64),
    );
    let proof = log.inclusion_proof(position).expect("position in range");
    assert!(
        verify_inclusion(&proof, root),
        "inclusion proof at position {} did not verify",
        position
    );
}
