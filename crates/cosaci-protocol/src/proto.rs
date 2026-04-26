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
use cosaci_core::capabilities::{Capabilities, JobRequirements};
use cosaci_core::retrieval::JobBundle;

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
        /// What this runner offers — platform, runtimes, cpu, memory.
        /// Coordinator stores this and consults it when filtering
        /// committee candidates by job requirements (issue #34).
        capabilities: Capabilities,
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
    /// `pipeline` is a typed sequence of steps from `cosaci-jobs`
    /// (issue #39) that the agent executes via
    /// `cosaci_jobs::execute_pipeline`. Step types whose executors
    /// haven't yet landed (#40 source fetch, #43 native exec, #54
    /// egress) report `StepStatus::NotImplemented` deterministically;
    /// the wire shape is forward-compatible with all step types.
    Assign {
        /// Job identifier the agent should attest under.
        job_id: u64,
        /// Typed pipeline definition.
        pipeline: cosaci_jobs::Pipeline,
        /// What this job requires of a runner — platform, runtimes,
        /// cpu, memory. Coordinator only sends `Assign` to runners
        /// whose registered capabilities satisfy these requirements
        /// (issue #34); the field is present on the wire so an agent
        /// can sanity-check its own match before executing.
        requirements: JobRequirements,
        /// Wall-clock deadline (unix ns) by which the attestation must
        /// be returned.
        deadline_unix_ns: i64,
    },
    /// Coordinator tells this agent no further work is coming.
    Shutdown,

    // ── Read API (Auditor / dashboard → Coordinator) ───────────────────
    /// Request the coordinator's record for a single job. The coord
    /// responds with [`Envelope::JobBundleResponse`] (verifiable
    /// bundle) on hit, or [`Envelope::JobNotFound`] on miss.
    GetJob {
        /// Job to look up.
        job_id: u64,
    },
    /// Request the coordinator's current Merkle log root + length.
    /// Coord responds with [`Envelope::LogRoot`].
    GetLogRoot,
    /// Coordinator's response to [`Envelope::GetJob`] on hit.
    JobBundleResponse(JobBundle),
    /// Coordinator's response to [`Envelope::GetJob`] on miss.
    JobNotFound {
        /// The job_id that was requested.
        job_id: u64,
    },
    /// Coordinator's response to [`Envelope::GetLogRoot`]. `root` is
    /// `None` for an empty log; `length` is the number of entries.
    LogRoot {
        /// Current Merkle root over all `length` entries, or `None`.
        root: Option<[u8; 32]>,
        /// Number of entries in the log.
        length: u64,
    },

    // ── Admin wire protocol (issue #53 follow-on) ──────────────────────
    /// Admin client → Coordinator: open an authenticated admin
    /// session. The client carries its ed25519 signing pubkey, a
    /// freshness timestamp, and a signature over the
    /// [`ADMIN_HELLO_CHALLENGE`] || `ts.to_le_bytes()`. Coordinator
    /// verifies (1) `SHA-256(pubkey)` is in the configured admin
    /// allowlist, (2) `ts` is within the freshness window, and (3)
    /// the signature verifies.
    AdminHello {
        /// Ed25519 verifying key of the admin client.
        admin_pubkey: [u8; 32],
        /// Wall-clock timestamp at hello time, unix ns.
        ts_unix_ns: u64,
        /// Signature over `[ADMIN_HELLO_CHALLENGE | ts_unix_ns.to_le_bytes()]`.
        #[serde(with = "BigArray")]
        signature: [u8; 64],
    },
    /// Coordinator's accept response to [`Envelope::AdminHello`].
    AdminWelcome,
    /// Coordinator's reject response to any admin envelope.
    AdminError {
        /// Short reason. v0.3 collapses signature/freshness/allowlist
        /// failures into "unauthorized" (the deliberately-merged
        /// shape that doesn't leak which admin keys are configured).
        reason: String,
    },
    /// Admin → Coordinator: list the entries in the enrollment file
    /// the coord was started with.
    AdminListAgents,
    /// Coordinator's response to [`Envelope::AdminListAgents`]. Each
    /// entry is `(runner_id, signing_fp, vrf_fp, enrolled_at_unix_ns,
    /// initial_reputation_thousandths)` — reputation is rendered as
    /// `(reputation * 1000).round() as u32` for clean wire encoding.
    AdminAgentList {
        /// Records, sorted by `runner_id`.
        entries: Vec<AdminAgentRecord>,
    },
    /// Admin → Coordinator: read the current Merkle log root + length.
    /// Same shape as [`Envelope::GetLogRoot`] but routed through the
    /// admin auth gate.
    AdminGetLogRoot,
    /// Coordinator's response to [`Envelope::AdminGetLogRoot`].
    AdminLogRoot {
        /// Current Merkle root over all `length` entries, or `None`
        /// for an empty log.
        root: Option<[u8; 32]>,
        /// Number of entries in the log.
        length: u64,
    },
}

/// Wire shape of one admin-list-agents record. Mirrors the
/// `cosaci-state::enrollment::EnrolledRecord` fields the admin CLI
/// renders.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdminAgentRecord {
    /// Runner identifier.
    pub runner_id: u64,
    /// SHA-256 fingerprint of the runner's signing pubkey.
    pub signing_fp: [u8; 32],
    /// SHA-256 fingerprint of the runner's VRF pubkey.
    pub vrf_fp: [u8; 32],
    /// Unix-ns timestamp the operator recorded at enrollment time.
    pub enrolled_at_unix_ns: i64,
    /// Initial reputation, encoded as `(reputation * 1000).round() as u32`
    /// (0..=1000 maps to 0.0..=1.0). Saturates at 1000.
    pub initial_reputation_thousandths: u32,
}

/// Fixed challenge prefix the admin client signs with `ts_unix_ns`
/// to authenticate. Binds the signature to the admin protocol so
/// a leaked admin signature can't be replayed against another
/// system that happens to use the same key for a different purpose.
pub const ADMIN_HELLO_CHALLENGE: &[u8] = b"cosaci-admin-hello-v1";

/// Default freshness window for [`Envelope::AdminHello`]'s
/// `ts_unix_ns`, in nanoseconds. ±60s on either side of the coord's
/// wall-clock — generous enough for clock skew between
/// administrative hosts, tight enough that a captured hello can't
/// be replayed days later.
pub const ADMIN_HELLO_FRESHNESS_NS: u64 = 60 * 1_000_000_000;

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
