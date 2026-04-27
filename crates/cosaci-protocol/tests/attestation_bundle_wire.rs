//! Wire round-trip tests for [`AttestationBundle`] (#108 PR 2 of N).
//!
//! Asserts:
//! 1. **Round-trip stability** — encode→decode→encode produces
//!    byte-equal CBOR for both empty-captures and populated
//!    bundles. This is what lets the agent's bundle and the
//!    coord's decoded view agree without re-serializing.
//! 2. **Captures-empty serialization** — `Vec::is_empty()` on
//!    `captures` causes the field to be skipped on the wire,
//!    so the outer envelope is shorter than a populated one.
//!    (We don't claim byte-equality with a pre-#108 bare
//!    `Attestation`, since the variant payload moved from
//!    `Attestation` to `AttestationBundle{...}`.)
//! 3. **Capture integrity** — each capture's
//!    `Sha256(bytes_inline) == sha256` is preserved through
//!    the wire. A signature-tampered attestation is detected
//!    by `verify_signature` (already covered upstream); a
//!    capture-tampered field is detected by re-hashing.

use std::io::Cursor;

use cosaci_core::attestation::{Attestation, AttestationResult};
use cosaci_core::signing::Keypair;
use cosaci_jobs::{CaptureKind, CapturedOutput};
use cosaci_protocol::proto::{AttestationBundle, Envelope, read_envelope, write_envelope};
use sha2::{Digest, Sha256};

fn sample_attestation() -> Attestation {
    let kp = Keypair::from_seed([0xa1; 32]);
    let mut att = Attestation {
        version: Attestation::VERSION,
        job_id: [0xab; 16],
        commit: [0x42; 32],
        runner_id: 7,
        result: AttestationResult::Pass,
        environment_hash: [0xee; 32],
        artifact_hash: [0x11; 32],
        timestamp_unix_ns: 1_700_000_000_000_000_000,
        signature: [0; 64],
    };
    att.sign_with(&kp);
    att
}

fn capture(name: &str, kind: CaptureKind, bytes: Vec<u8>) -> CapturedOutput {
    let sha256: [u8; 32] = Sha256::digest(&bytes).into();
    CapturedOutput {
        step_index: 1,
        name: name.into(),
        kind,
        sha256,
        length: bytes.len() as u64,
        bytes_inline: bytes,
    }
}

fn write_then_read(env: &Envelope) -> Envelope {
    let mut buf = Vec::new();
    write_envelope(&mut buf, env).expect("write");
    let mut cursor = Cursor::new(buf);
    read_envelope(&mut cursor).expect("read")
}

#[test]
fn empty_captures_round_trips() {
    let att = sample_attestation();
    let bundle = AttestationBundle::from_attestation(att.clone());
    let env = Envelope::SubmitAttestation(bundle);
    let decoded = write_then_read(&env);
    let Envelope::SubmitAttestation(decoded_bundle) = decoded else {
        panic!("decoded variant changed");
    };
    assert_eq!(decoded_bundle.attestation, att);
    assert!(decoded_bundle.captures.is_empty());
}

#[test]
fn populated_captures_round_trip_byte_equal() {
    let att = sample_attestation();
    let captures = vec![
        capture(
            "build.stdout",
            CaptureKind::Stdout,
            b"compile ok\n".to_vec(),
        ),
        capture(
            "build.stderr",
            CaptureKind::Stderr,
            b"warning: foo\n".to_vec(),
        ),
    ];
    let bundle = AttestationBundle {
        attestation: att,
        captures,
    };
    let env = Envelope::SubmitAttestation(bundle);

    // Encode once, decode, re-encode. Byte equality of the two
    // encodings is the canonical-CBOR claim.
    let mut buf1 = Vec::new();
    write_envelope(&mut buf1, &env).expect("write 1");
    let mut cursor = Cursor::new(buf1.clone());
    let decoded = read_envelope(&mut cursor).expect("read");
    let mut buf2 = Vec::new();
    write_envelope(&mut buf2, &decoded).expect("write 2");
    assert_eq!(buf1, buf2, "re-encode produced different CBOR bytes");
}

#[test]
fn empty_captures_is_shorter_on_wire_than_populated() {
    // skip_serializing_if = "Vec::is_empty" makes the field
    // disappear from the CBOR map. A populated bundle is
    // strictly larger than an empty one with the same
    // attestation.
    let att = sample_attestation();
    let empty = AttestationBundle::from_attestation(att.clone());
    let populated = AttestationBundle {
        attestation: att,
        captures: vec![capture("x", CaptureKind::Stdout, b"ten-bytes!".to_vec())],
    };
    let mut buf_empty = Vec::new();
    let mut buf_pop = Vec::new();
    write_envelope(&mut buf_empty, &Envelope::SubmitAttestation(empty)).expect("write empty");
    write_envelope(&mut buf_pop, &Envelope::SubmitAttestation(populated)).expect("write pop");
    assert!(
        buf_empty.len() < buf_pop.len(),
        "empty captures should not be serialized: empty={} pop={}",
        buf_empty.len(),
        buf_pop.len()
    );
}

#[test]
fn capture_sha256_survives_wire() {
    // Round-trip a populated bundle; re-hash each decoded
    // capture's bytes_inline and assert it matches the
    // recorded sha256. This is the integrity claim for
    // captures over the wire.
    let att = sample_attestation();
    let bytes = b"some output bytes that aren't aligned to a power of two".to_vec();
    let cap = capture("payload", CaptureKind::Stdout, bytes);
    let bundle = AttestationBundle {
        attestation: att,
        captures: vec![cap],
    };
    let env = Envelope::SubmitAttestation(bundle);
    let decoded = write_then_read(&env);
    let Envelope::SubmitAttestation(decoded_bundle) = decoded else {
        panic!("variant changed");
    };
    let cap = &decoded_bundle.captures[0];
    let recomputed: [u8; 32] = Sha256::digest(&cap.bytes_inline).into();
    assert_eq!(
        recomputed, cap.sha256,
        "capture sha256 doesn't match bytes_inline after wire round-trip"
    );
    assert_eq!(cap.length as usize, cap.bytes_inline.len());
}
