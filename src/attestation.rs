//! Attestation format and canonicalization.
//!
//! Source: `SPEC.md` §10 / `hypotheses/attestation-roundtrip.md` + `hypotheses/
//! attestation-canonicalization.md` (class A, load-bearing — the Merkle log,
//! replay protection, and tamper rejection all assume `hash(attestation)` is
//! a stable identity).
//!
//! Primitive commitment (2026-04-24): canonical encoding is CBOR via
//! `ciborium`, hashed with SHA-256. The `Attestation` struct uses only
//! fixed-size byte arrays and fixed-width integers to eliminate encoding
//! ambiguity at the semantic layer; ciborium's deterministic struct-as-map
//! serialization with declaration-ordered fields then produces stable bytes.

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use sha2::{Digest, Sha256};

use crate::signing::{verify as sig_verify, Keypair, Signature, VerifyingKey};

/// Result of a job as attested by a runner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttestationResult {
    Pass,
    Fail,
}

/// A signed claim by one runner about one job's outcome.
///
/// All identifier and hash fields are fixed-size byte arrays to keep
/// encoding unambiguous across implementations. The timestamp is unix
/// nanoseconds (signed i64 to allow pre-epoch values Hegel might draw).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    pub version: u8,
    pub job_id: [u8; 16],
    pub commit: [u8; 32],
    pub runner_id: u64,
    pub result: AttestationResult,
    pub environment_hash: [u8; 32],
    pub artifact_hash: [u8; 32],
    pub timestamp_unix_ns: i64,
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

impl Attestation {
    /// Sentinel for the currently-supported schema version.
    pub const VERSION: u8 = 1;
}

/// Canonical byte encoding of an attestation. Stable across serializations
/// of semantically-equal values; any field change produces different bytes.
///
/// # Panics
///
/// Does not panic under normal use: `Attestation` has no fields that can
/// fail serialization (no `Result`-bearing `Serialize` impls). The `.expect`
/// is a last-line assertion on ciborium's internal invariants.
#[must_use]
pub fn canonicalize(a: &Attestation) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(a, &mut bytes).expect("ciborium serialization of Attestation is infallible");
    bytes
}

/// SHA-256 digest of the canonical encoding. This is the stable content
/// identifier used by the Merkle log, replay index, and trust chain.
#[must_use]
pub fn hash(a: &Attestation) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(canonicalize(a));
    hasher.finalize().into()
}

/// Parse an attestation from its canonical encoding.
///
/// # Errors
///
/// Returns a ciborium decode error if the input is not a valid canonical
/// encoding of an `Attestation`.
pub fn decanonicalize(bytes: &[u8]) -> Result<Attestation, ciborium::de::Error<std::io::Error>> {
    ciborium::from_reader(bytes)
}

impl Attestation {
    /// Canonical byte encoding of this attestation with the signature
    /// field zeroed out. This is the message that gets signed — the
    /// signature cannot cover itself.
    #[must_use]
    pub fn canonical_signing_input(&self) -> Vec<u8> {
        let mut tmp = self.clone();
        tmp.signature = [0_u8; 64];
        canonicalize(&tmp)
    }

    /// Sign this attestation in place. Overwrites the `signature` field
    /// with an Ed25519 signature over `canonical_signing_input`.
    pub fn sign_with(&mut self, kp: &Keypair) {
        let msg = self.canonical_signing_input();
        let sig = kp.sign(&msg);
        self.signature = sig.to_bytes();
    }

    /// Verify this attestation's signature against `pk`. Returns `true`
    /// iff `pk` produced the signature over `canonical_signing_input`.
    #[must_use]
    pub fn verify_signature(&self, pk: &VerifyingKey) -> bool {
        let msg = self.canonical_signing_input();
        let sig = Signature::from_bytes(&self.signature);
        sig_verify(pk, &msg, &sig).is_ok()
    }
}
