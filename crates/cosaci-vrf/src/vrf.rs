//! VRF-based assignment via `schnorrkel` (sr25519 Ristretto-Schnorr VRF).
//!
//! Source: `SPEC.md` §7.1 / `hypotheses/vrf-assignment-uniformity.md`
//! (class A). The VRF gives a deterministic-but-unpredictable output per
//! `(secret_key, input)` with a short proof that a public key can verify.
//!
//! Primitive: `schnorrkel` 0.11 (Polkadot's VRF). RFC: Ristretto255-based,
//! with merlin transcripts for input binding. We namespace with a fixed
//! context label `"cosaci-vrf"` to prevent cross-protocol reuse.

use merlin::Transcript;
use schnorrkel::vrf::{VRF_PREOUT_LENGTH, VRF_PROOF_LENGTH, VRFPreOut, VRFProof};
use schnorrkel::{ExpansionMode, Keypair, MiniSecretKey, PublicKey};

/// 32-byte seed used to derive a VRF keypair.
pub type Seed = [u8; 32];

/// VRF output bytes (32).
pub type VrfOutput = [u8; VRF_PREOUT_LENGTH];

/// VRF proof bytes (64).
pub type VrfProofBytes = [u8; VRF_PROOF_LENGTH];

/// Serialized VRF public key (32 bytes).
pub type VrfPublicKeyBytes = [u8; 32];

/// Failure modes surfaced to callers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VrfError {
    /// Proof bytes couldn't be parsed, or verification failed.
    InvalidProof,
    /// Public-key bytes couldn't be parsed.
    InvalidPublicKey,
    /// VRF output bytes couldn't be parsed as a Ristretto compressed point.
    InvalidOutput,
}

const CONTEXT: &[u8] = b"cosaci-vrf";

fn transcript(input: &[u8]) -> Transcript {
    let mut t = Transcript::new(CONTEXT);
    t.append_message(b"input", input);
    t
}

/// A VRF keypair derived from a 32-byte seed.
pub struct VrfKeypair {
    keypair: Keypair,
}

impl VrfKeypair {
    /// Deterministic keypair from a 32-byte seed. Same seed yields the
    /// same public key and the same VRF output for any given input.
    ///
    /// # Panics
    ///
    /// Does not panic — `MiniSecretKey::from_bytes` succeeds on any 32
    /// bytes, and `expand_to_keypair` is infallible.
    #[must_use]
    pub fn from_seed(seed: Seed) -> Self {
        let mini = MiniSecretKey::from_bytes(&seed)
            .expect("MiniSecretKey::from_bytes on 32 bytes is infallible");
        let keypair = mini.expand_to_keypair(ExpansionMode::Uniform);
        Self { keypair }
    }

    /// This keypair's public key, serialized.
    #[must_use]
    pub fn public_key_bytes(&self) -> VrfPublicKeyBytes {
        self.keypair.public.to_bytes()
    }

    /// Evaluate the VRF at `input`. Returns `(output, proof)`. The output
    /// is a deterministic function of `(secret_key, input)` — same input
    /// under the same key gives the same output. The proof is *not*
    /// deterministic (the underlying Schnorr signature uses randomness)
    /// but every proof from this `(key, input)` pair verifies.
    #[must_use]
    pub fn evaluate(&self, input: &[u8]) -> (VrfOutput, VrfProofBytes) {
        let t = transcript(input);
        let (signed, proof, _batchable) = self.keypair.vrf_sign(t);
        let output = *signed.as_output_bytes();
        let proof_bytes = proof.to_bytes();
        (output, proof_bytes)
    }
}

/// Verify that `output` is the VRF of `input` under the key `pk_bytes`,
/// given `proof_bytes` as the non-interactive witness.
///
/// # Errors
///
/// Returns `VrfError::InvalidPublicKey` if the key bytes are not a valid
/// Ristretto compressed point, `VrfError::InvalidOutput` if the output
/// bytes aren't a valid point, or `VrfError::InvalidProof` if the proof
/// bytes are malformed or verification fails.
pub fn verify(
    pk_bytes: &VrfPublicKeyBytes,
    input: &[u8],
    output: &VrfOutput,
    proof_bytes: &VrfProofBytes,
) -> Result<(), VrfError> {
    let pk = PublicKey::from_bytes(pk_bytes).map_err(|_| VrfError::InvalidPublicKey)?;
    let preout = VRFPreOut::from_bytes(output).map_err(|_| VrfError::InvalidOutput)?;
    let proof = VRFProof::from_bytes(proof_bytes).map_err(|_| VrfError::InvalidProof)?;
    let t = transcript(input);
    pk.vrf_verify(t, &preout, &proof)
        .map(|_| ())
        .map_err(|_| VrfError::InvalidProof)
}
