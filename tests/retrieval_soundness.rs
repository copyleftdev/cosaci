//! Property tests for `cosaci-core::retrieval`.
//!
//! Encodes the falsifiable claims of `hypotheses/retrieval-soundness.md`
//! (issue #44, class A). Five properties:
//!
//!   1. Every recorded job retrieves a bundle whose `merkle_proof`
//!      verifies against its own `log_root`.
//!   2. Mutating any byte of the proof's `entry` causes verification
//!      to fail.
//!   3. Mutating any byte of the bundle's `log_root` causes
//!      verification to fail.
//!   4. Building the bundle twice on the same state yields a CBOR
//!      round-trip-equal result.
//!   5. Requesting an unrecorded job_id returns `None`.
//!
//! The retrieval surface is pure: no I/O, no clocks, no concurrency.
//! Hegel draws the registry / log shape; assertions are pointwise
//! universal.

use std::collections::HashMap;

use cosaci::attestation::{Attestation, AttestationResult};
use cosaci::merkle_log::{Hash, MerkleLog, hash_bytes, verify_inclusion};
use cosaci::retrieval::{JobBundle, JobRecord, build_bundle};
use hegel::{TestCase, generators};

// ────────────────────────────────────────────────────────────────────────
// Hegel generators
// ────────────────────────────────────────────────────────────────────────

fn draw_hash(tc: &TestCase) -> Hash {
    let v: Vec<u8> = tc.draw(generators::binary().min_size(32).max_size(32));
    let mut h = [0_u8; 32];
    h.copy_from_slice(&v);
    h
}

/// Placeholder attestation. The retrieval property doesn't exercise
/// signature paths (those are covered by `attestation-canonicalization`
/// and `tamper-rejection`); what matters here is that attestations
/// round-trip through CBOR inside the bundle.
fn placeholder_attestation(tc: &TestCase, runner_id: u64) -> Attestation {
    Attestation {
        version: Attestation::VERSION,
        job_id: {
            let v: Vec<u8> = tc.draw(generators::binary().min_size(16).max_size(16));
            let mut a = [0_u8; 16];
            a.copy_from_slice(&v);
            a
        },
        commit: draw_hash(tc),
        runner_id,
        result: AttestationResult::Pass,
        environment_hash: draw_hash(tc),
        artifact_hash: draw_hash(tc),
        timestamp_unix_ns: tc.draw(generators::integers::<i64>()),
        signature: [0_u8; 64],
    }
}

/// Build up a paired `(records, log)` state by drawing N jobs. Each
/// job:
///  - draws a unique job_id
///  - draws a few placeholder attestations
///  - draws a consensus_artifact
///  - appends the consensus_artifact to the log and records the
///    `(position, length)` freeze-frame
fn draw_state(tc: &TestCase, max_jobs: usize) -> (HashMap<u64, JobRecord>, MerkleLog) {
    let n = tc.draw(
        generators::integers::<usize>()
            .min_value(0)
            .max_value(max_jobs),
    );
    let mut log = MerkleLog::new();
    let mut records: HashMap<u64, JobRecord> = HashMap::new();
    for i in 0..n {
        let job_id = (i as u64) + 1;
        let pipeline_hash = draw_hash(tc);
        let consensus_artifact = draw_hash(tc);
        let committee_size = tc.draw(generators::integers::<usize>().min_value(1).max_value(3));
        let committee_attestations: Vec<Attestation> = (0..committee_size)
            .map(|r| placeholder_attestation(tc, r as u64))
            .collect();
        let pos = log.append(consensus_artifact);
        let length = log.len();
        records.insert(
            job_id,
            JobRecord {
                job_id,
                pipeline_hash,
                committee_attestations,
                consensus_artifact,
                log_position: pos,
                log_length_at_anchor: length,
            },
        );
    }
    (records, log)
}

// ────────────────────────────────────────────────────────────────────────
// Property 1 — every recorded job retrieves a verifying bundle.
// ────────────────────────────────────────────────────────────────────────
#[hegel::test]
fn proof_verifies_for_every_recorded_job(tc: TestCase) {
    let (records, log) = draw_state(&tc, 16);
    for &job_id in records.keys() {
        let bundle = build_bundle(&records, &log, job_id)
            .unwrap_or_else(|| panic!("recorded job {job_id} returned None"));
        assert!(
            verify_inclusion(&bundle.merkle_proof, bundle.log_root),
            "verify_inclusion failed for job {job_id}"
        );
        assert_eq!(bundle.merkle_proof.entry, bundle.consensus_artifact);
        assert_eq!(bundle.merkle_proof.position, bundle.log_position);
        assert_eq!(
            bundle.merkle_proof.length_at_proof,
            bundle.log_length_at_anchor
        );
    }
}

// ────────────────────────────────────────────────────────────────────────
// Property 2 — flipping a byte of the entry breaks verification.
// ────────────────────────────────────────────────────────────────────────
#[hegel::test]
fn tamper_in_entry_is_rejected(tc: TestCase) {
    let (records, log) = draw_state(&tc, 16);
    if records.is_empty() {
        return;
    }
    let job_id = *records.keys().next().expect("non-empty");
    let mut bundle = build_bundle(&records, &log, job_id).expect("recorded job");
    let byte_index = tc.draw(generators::integers::<usize>().min_value(0).max_value(31));
    let bit_mask: u8 = tc.draw(generators::integers::<u8>().min_value(1).max_value(255));
    bundle.merkle_proof.entry[byte_index] ^= bit_mask;
    assert!(
        !verify_inclusion(&bundle.merkle_proof, bundle.log_root),
        "tampered entry verified — proof must bind entry bytes"
    );
}

// ────────────────────────────────────────────────────────────────────────
// Property 3 — flipping a byte of log_root breaks verification.
// ────────────────────────────────────────────────────────────────────────
#[hegel::test]
fn tamper_in_root_is_rejected(tc: TestCase) {
    let (records, log) = draw_state(&tc, 16);
    if records.is_empty() {
        return;
    }
    let job_id = *records.keys().next().expect("non-empty");
    let mut bundle = build_bundle(&records, &log, job_id).expect("recorded job");
    let byte_index = tc.draw(generators::integers::<usize>().min_value(0).max_value(31));
    let bit_mask: u8 = tc.draw(generators::integers::<u8>().min_value(1).max_value(255));
    bundle.log_root[byte_index] ^= bit_mask;
    assert!(
        !verify_inclusion(&bundle.merkle_proof, bundle.log_root),
        "tampered root verified — proof must commit to a single root"
    );
}

// ────────────────────────────────────────────────────────────────────────
// Property 4 — bundle is byte-stable across calls (CBOR equality).
// ────────────────────────────────────────────────────────────────────────
#[hegel::test]
fn bundle_is_stable_across_calls(tc: TestCase) {
    let (records, log) = draw_state(&tc, 16);
    for &job_id in records.keys() {
        let a = build_bundle(&records, &log, job_id).expect("recorded");
        let b = build_bundle(&records, &log, job_id).expect("recorded");
        let a_bytes = encode_bundle(&a);
        let b_bytes = encode_bundle(&b);
        assert_eq!(
            a_bytes, b_bytes,
            "bundle for job {job_id} not byte-stable across calls"
        );
    }
}

// ────────────────────────────────────────────────────────────────────────
// Property 5 — unknown job returns None.
// ────────────────────────────────────────────────────────────────────────
#[hegel::test]
fn unknown_job_returns_none(tc: TestCase) {
    let (records, log) = draw_state(&tc, 16);
    let absent = (records.len() as u64) + 1024;
    assert!(
        !records.contains_key(&absent),
        "drew an unrecorded job_id that turned out to be present"
    );
    assert!(
        build_bundle(&records, &log, absent).is_none(),
        "unrecorded job {absent} returned Some"
    );
}

// ────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────

fn encode_bundle(b: &JobBundle) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(b, &mut bytes).expect("CBOR encode JobBundle");
    bytes
}

// ────────────────────────────────────────────────────────────────────────
// Smoke
// ────────────────────────────────────────────────────────────────────────
#[test]
fn smoke_three_jobs_round_trip() {
    let mut log = MerkleLog::new();
    let mut records: HashMap<u64, JobRecord> = HashMap::new();
    for i in 1_u64..=3 {
        let artifact = hash_bytes(&i.to_le_bytes());
        let pos = log.append(artifact);
        let length = log.len();
        records.insert(
            i,
            JobRecord {
                job_id: i,
                pipeline_hash: hash_bytes(b"pipeline"),
                committee_attestations: Vec::new(),
                consensus_artifact: artifact,
                log_position: pos,
                log_length_at_anchor: length,
            },
        );
    }
    for i in 1_u64..=3 {
        let bundle = build_bundle(&records, &log, i).expect("recorded");
        assert!(verify_inclusion(&bundle.merkle_proof, bundle.log_root));
        assert_eq!(bundle.consensus_artifact, hash_bytes(&i.to_le_bytes()));
    }
}
