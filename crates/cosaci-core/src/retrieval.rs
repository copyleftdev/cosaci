//! Read-side retrieval API — pure functions over a job registry +
//! Merkle log that produce verifiable bundles for external auditors.
//!
//! Source: `SPEC.md` §10.4 / `hypotheses/retrieval-soundness.md` (issue
//! #44, class A). Retrieval is pure: given the same `(records, log)`
//! state, [`build_bundle`] returns byte-identical bundles, and every
//! produced bundle verifies under
//! [`crate::merkle_log::verify_inclusion`] against the bundle's own
//! `log_root`.

use std::collections::HashMap;
use std::hash::BuildHasher;

use serde::{Deserialize, Serialize};

use crate::attestation::Attestation;
use crate::merkle_log::{Hash, InclusionProof, MerkleLog, Store};

/// One coordinator-side record per committed job. Captures the
/// information needed to produce a [`JobBundle`] for any future
/// retrieval query against this `job_id`.
///
/// The pair `(log_position, log_length_at_anchor)` is the freeze-frame
/// that lets every future retrieval rebuild the same proof: the proof
/// is computed against `root_at(log_length_at_anchor)`, which is a
/// pure function of the first `log_length_at_anchor` entries and is
/// stable forever once those entries are appended.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobRecord {
    /// Job identifier.
    pub job_id: u64,
    /// SHA-256 of the canonical CBOR encoding of the executed pipeline.
    pub pipeline_hash: [u8; 32],
    /// Every signed attestation the committee returned (signature-valid
    /// only — bad-signature attestations are dropped before recording).
    pub committee_attestations: Vec<Attestation>,
    /// The artifact hash the quorum agreed on.
    pub consensus_artifact: Hash,
    /// 0-indexed position of the consensus artifact in the Merkle log.
    pub log_position: u64,
    /// Length of the Merkle log at the moment this job was anchored.
    /// Inclusion proofs are generated against this length; recomputing
    /// later against the same length always yields the same proof.
    pub log_length_at_anchor: u64,
}

/// Verifiable retrieval bundle. Every field is wire-shippable; an
/// external auditor with no other context can verify the bundle by:
///
/// 1. Verifying every signature in `committee_attestations` against
///    the corresponding registered runner pubkey.
/// 2. Calling [`crate::merkle_log::verify_inclusion`]`(merkle_proof,
///    log_root)`.
/// 3. (Optionally) recomputing `pipeline_hash` from a separately-fetched
///    pipeline definition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobBundle {
    /// Job identifier.
    pub job_id: u64,
    /// SHA-256 of the canonical CBOR encoding of the executed pipeline.
    pub pipeline_hash: [u8; 32],
    /// Every signature-valid attestation the committee returned.
    pub committee_attestations: Vec<Attestation>,
    /// The artifact hash the quorum agreed on.
    pub consensus_artifact: Hash,
    /// Inclusion proof of `consensus_artifact` at `log_position` against
    /// the Merkle root over the first `log_length_at_anchor` entries.
    pub merkle_proof: InclusionProof,
    /// The Merkle root that `merkle_proof` verifies against.
    pub log_root: Hash,
    /// 0-indexed position of `consensus_artifact` in the log.
    pub log_position: u64,
    /// Log length the proof + root were frozen at.
    pub log_length_at_anchor: u64,
}

/// Build a [`JobBundle`] for `job_id` from a registry + log snapshot.
/// Returns `None` if the job isn't recorded, or if the recorded
/// `(log_position, log_length_at_anchor)` is inconsistent with the
/// log (e.g. the log was truncated externally).
///
/// Pure: invoking this function twice on the same `(records, log,
/// job_id)` produces byte-identical bundles.
#[must_use]
pub fn build_bundle<S: Store, H: BuildHasher>(
    records: &HashMap<u64, JobRecord, H>,
    log: &MerkleLog<S>,
    job_id: u64,
) -> Option<JobBundle> {
    let r = records.get(&job_id)?;
    let proof = log.inclusion_proof_at(r.log_position, r.log_length_at_anchor)?;
    let root = log.root_at(r.log_length_at_anchor)?;
    Some(JobBundle {
        job_id: r.job_id,
        pipeline_hash: r.pipeline_hash,
        committee_attestations: r.committee_attestations.clone(),
        consensus_artifact: r.consensus_artifact,
        merkle_proof: proof,
        log_root: root,
        log_position: r.log_position,
        log_length_at_anchor: r.log_length_at_anchor,
    })
}
