//! Wire protocol between coordinator and agent.
//!
//! Messages are CBOR-encoded `Envelope` values prefixed with a 4-byte
//! big-endian length. TCP framing is the responsibility of the caller;
//! `read_envelope` / `write_envelope` drive framed reads / writes against
//! any `std::io::{Read, Write}` target (including `TcpStream`).
//!
//! v0.1 is plaintext. Wrapping the `TcpStream` in a rustls `Stream<_, _>`
//! (using `src/tls.rs` as the handshake harness, plus a real TCP-backed
//! `ServerConnection` / `ClientConnection`) is a drop-in at this layer.

use std::io::{Read, Write};

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use cosaci_core::attestation::Attestation;

/// Fixed VRF challenge for the registration proof. Binds
/// `(vrf_pubkey, this string)` to a unique output that only the
/// holder of the matching secret key could have produced. Acts as a
/// possession-of-secret-key proof at registration time.
pub const VRF_REGISTRATION_CHALLENGE: &[u8] = b"cosaci-runner-registration-v1";

/// All messages flowing between coordinator and agent.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Envelope {
    // ── Agent → Coordinator ────────────────────────────────────────────
    /// Agent announces itself and its capabilities.
    ///
    /// `vrf_output` and `vrf_proof` are the VRF evaluation of
    /// [`VRF_REGISTRATION_CHALLENGE`] under `vrf_pubkey`. The
    /// coordinator verifies the proof on receipt; agents that can't
    /// produce a valid proof for the claimed VRF pubkey are rejected.
    Register {
        /// Runner identifier the agent is announcing itself as.
        runner_id: u64,
        /// Ed25519 verifying key the runner will sign attestations with.
        signing_pubkey: [u8; 32],
        /// Schnorrkel sr25519 VRF public key.
        vrf_pubkey: [u8; 32],
        /// VRF output for [`VRF_REGISTRATION_CHALLENGE`].
        vrf_output: [u8; 32],
        /// Proof that `vrf_output` was produced by the holder of
        /// `vrf_pubkey`'s secret key.
        #[serde(with = "BigArray")]
        vrf_proof: [u8; 64],
        /// Stake the runner is committing.
        stake: u64,
    },
    /// Agent's VRF evaluation of the per-job seed. Sent in response to
    /// a [`Envelope::JobSeed`]. Coordinator collects claims from the
    /// whole fleet, verifies each proof, and picks the committee as the
    /// top-k by lexicographically smallest `vrf_output`.
    VrfClaim {
        /// Job the claim is for. Must match the most recent
        /// [`Envelope::JobSeed`] sent to this agent.
        job_id: u64,
        /// VRF output for the job seed.
        vrf_output: [u8; 32],
        /// Proof that `vrf_output` was produced by the registered
        /// VRF public key over the job seed.
        #[serde(with = "BigArray")]
        vrf_proof: [u8; 64],
    },
    /// Agent returns a signed attestation for an assigned job.
    SubmitAttestation(Attestation),

    // ── Coordinator → Agent ────────────────────────────────────────────
    /// Coordinator acknowledges a `Register`.
    RegisterAck,
    /// Coordinator broadcasts a per-job seed to every registered agent.
    /// Each agent must respond with a [`Envelope::VrfClaim`] computed
    /// against this seed before committee selection runs.
    JobSeed {
        /// Job identifier this seed corresponds to.
        job_id: u64,
        /// Per-job seed bytes; agent runs VRF over this.
        seed: [u8; 32],
    },
    /// Coordinator assigns a job to a committee member (only sent to
    /// agents whose VRF claim won a slot).
    ///
    /// `module` is binary `.wasm` bytes obeying the v0.2 ABI defined in
    /// `cosaci-wasm` (exports `add(i32, i32) -> i32`). `args_cbor` is
    /// the CBOR-encoded `(i32, i32)` tuple that `cosaci_wasm::execute`
    /// decodes to invoke the export.
    Assign {
        /// Job identifier the agent should attest under.
        job_id: u64,
        /// Binary `.wasm` module bytes the agent should compile + run.
        module: Vec<u8>,
        /// CBOR-encoded argument tuple for the module's export.
        args_cbor: Vec<u8>,
        /// Wall-clock deadline (unix ns) by which the attestation must
        /// be returned.
        deadline_unix_ns: i64,
    },
    /// Coordinator tells this agent no further work is coming.
    Shutdown,
}

/// Maximum envelope payload size (16 MiB). Sized to accept real-world
/// WASM modules (issue #6) while still bounding the damage a malformed
/// length prefix can do (vs. a 4 GiB allocation if unbounded).
const MAX_ENVELOPE_BYTES: usize = 16 << 20;

/// Write an `Envelope` as `[4 byte BE length][CBOR bytes]`.
///
/// # Errors
///
/// Returns an I/O error if the underlying writer fails, or
/// `InvalidData` if the encoded envelope exceeds `MAX_ENVELOPE_BYTES`.
pub fn write_envelope<W: Write>(w: &mut W, env: &Envelope) -> std::io::Result<()> {
    let mut buf = Vec::new();
    ciborium::into_writer(env, &mut buf).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("cbor encode: {e}"))
    })?;
    if buf.len() > MAX_ENVELOPE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("envelope {} > max {}", buf.len(), MAX_ENVELOPE_BYTES),
        ));
    }
    let len = buf.len() as u32;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(&buf)?;
    w.flush()?;
    Ok(())
}

/// Read a single `Envelope` from `[4 byte BE length][CBOR bytes]`.
///
/// # Errors
///
/// Returns an I/O error if the underlying reader fails, `InvalidData`
/// if the length prefix declares more than `MAX_ENVELOPE_BYTES`, or
/// `InvalidData` if the CBOR payload fails to decode.
pub fn read_envelope<R: Read>(r: &mut R) -> std::io::Result<Envelope> {
    let mut len_bytes = [0_u8; 4];
    r.read_exact(&mut len_bytes)?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > MAX_ENVELOPE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("incoming envelope declared {len} bytes > max {MAX_ENVELOPE_BYTES}"),
        ));
    }
    let mut buf = vec![0_u8; len];
    r.read_exact(&mut buf)?;
    ciborium::from_reader::<Envelope, _>(buf.as_slice()).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("cbor decode: {e}"))
    })
}
