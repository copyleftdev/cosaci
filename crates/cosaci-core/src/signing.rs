//! Ed25519 signing wrapper.
//!
//! Source: `SPEC.md` §9.1 (tamper rejection) / `hypotheses/tamper-rejection.md`
//! (class A). Wraps `ed25519-dalek` 2.x with a narrower surface: 32-byte seeds,
//! raw-bytes signing, strict verification. Properties are exercised in
//! `tests/tamper_rejection.rs`.
//!
//! This module tests our wrapper's correct usage of `ed25519-dalek`, not the
//! correctness of Ed25519 itself.

use ed25519_dalek::Signer;

pub use ed25519_dalek::{Signature, SignatureError, VerifyingKey};

/// A keypair bound to a 32-byte seed.
#[derive(Clone)]
pub struct Keypair {
    signing: ed25519_dalek::SigningKey,
}

impl Keypair {
    /// Construct a keypair from a 32-byte seed. Deterministic per RFC 8032:
    /// identical seeds yield identical public keys and signatures.
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing: ed25519_dalek::SigningKey::from_bytes(&seed),
        }
    }

    /// Verifying key (public half) of this keypair.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    /// Sign a byte string. Ed25519 is deterministic; signing the same `msg`
    /// twice yields the same signature.
    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.signing.sign(msg)
    }
}

/// Verify a signature with RFC 8032 strict rules (rejects non-canonical
/// signatures and low-order public-key components).
///
/// # Errors
///
/// Returns `Err(SignatureError)` if the signature is invalid for the given
/// `(pk, msg)` pair or fails strict canonicalization checks.
pub fn verify(pk: &VerifyingKey, msg: &[u8], sig: &Signature) -> Result<(), SignatureError> {
    pk.verify_strict(msg, sig)
}
