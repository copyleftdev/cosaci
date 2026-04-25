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

use cosaci_core::attestation::Attestation;

/// All messages flowing between coordinator and agent.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Envelope {
    // ── Agent → Coordinator ────────────────────────────────────────────
    /// Agent announces itself and its capabilities.
    Register {
        runner_id: u64,
        signing_pubkey: [u8; 32],
        vrf_pubkey: [u8; 32],
        stake: u64,
    },
    /// Agent returns a signed attestation for an assigned job.
    SubmitAttestation(Attestation),

    // ── Coordinator → Agent ────────────────────────────────────────────
    /// Coordinator acknowledges a `Register`.
    RegisterAck,
    /// Coordinator assigns a job to this agent.
    Assign {
        job_id: u64,
        a: i32,
        b: i32,
        deadline_unix_ns: i64,
    },
    /// Coordinator tells this agent no further work is coming.
    Shutdown,
}

/// Maximum envelope payload size (1 MiB). Prevents a malformed length
/// prefix from causing a 4 GiB allocation.
const MAX_ENVELOPE_BYTES: usize = 1 << 20;

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
            format!(
                "incoming envelope declared {} bytes > max {}",
                len, MAX_ENVELOPE_BYTES
            ),
        ));
    }
    let mut buf = vec![0_u8; len];
    r.read_exact(&mut buf)?;
    ciborium::from_reader::<Envelope, _>(buf.as_slice()).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("cbor decode: {e}"))
    })
}
