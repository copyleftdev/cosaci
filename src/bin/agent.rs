//! CosaCI agent — connects to the coordinator, registers, executes
//! assigned jobs in the WASM sandbox, and returns signed attestations.
//!
//! Run with `cargo run --bin agent -- --id 0 --addr 127.0.0.1:7878
//!                                    --stake 100`.

use std::env;
use std::net::TcpStream;

use cosaci::attestation::{Attestation, AttestationResult};
use cosaci::proto::{read_envelope, write_envelope, Envelope};
use cosaci::quorum::RunnerId;
use cosaci::signing::Keypair;
use cosaci::vrf::VrfKeypair;
use cosaci::wasm_runtime::{execute_add, output_hash};

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let id: u64 = arg_or(&args, "--id", "0").parse().expect("id u64");
    let addr = arg_or(&args, "--addr", "127.0.0.1:7878");
    let stake: u64 = arg_or(&args, "--stake", "100").parse().expect("stake u64");

    let runner_id: RunnerId = id;

    // Deterministic per-id seeds (matches the demo's convention).
    let mut signing_seed = [0_u8; 32];
    let mut vrf_seed = [0_u8; 32];
    signing_seed[..8].copy_from_slice(&id.to_le_bytes());
    vrf_seed[..8].copy_from_slice(&id.to_le_bytes());
    vrf_seed[8] = 0xff;
    let signing = Keypair::from_seed(signing_seed);
    let signing_pk = signing.verifying_key().to_bytes();
    let vrf = VrfKeypair::from_seed(vrf_seed);
    let vrf_pk = vrf.public_key_bytes();

    println!("[agent {id}] connecting to {addr}");
    let mut stream = TcpStream::connect(&addr)?;
    stream.set_nodelay(true)?;

    // Register
    write_envelope(
        &mut stream,
        &Envelope::Register {
            runner_id,
            signing_pubkey: signing_pk,
            vrf_pubkey: vrf_pk,
            stake,
        },
    )?;

    // Expect RegisterAck
    match read_envelope(&mut stream)? {
        Envelope::RegisterAck => println!("[agent {id}] registered"),
        other => {
            eprintln!("[agent {id}] expected RegisterAck, got {other:?}");
            return Ok(());
        }
    }

    // Main loop: process Assign / Shutdown.
    loop {
        let env = match read_envelope(&mut stream) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("[agent {id}] stream closed: {e}");
                break;
            }
        };
        match env {
            Envelope::Assign {
                job_id,
                a,
                b,
                deadline_unix_ns,
            } => {
                println!("[agent {id}] assigned job {job_id}: add({a}, {b})");
                let result = execute_add(a, b).map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::Other, format!("wasm: {e}"))
                })?;
                let artifact = output_hash(result);
                let mut att = Attestation {
                    version: Attestation::VERSION,
                    job_id: u64_to_uuid(job_id),
                    commit: [0x42; 32],
                    runner_id,
                    result: AttestationResult::Pass,
                    environment_hash: [0xee; 32],
                    artifact_hash: artifact,
                    timestamp_unix_ns: deadline_unix_ns,
                    signature: [0_u8; 64],
                };
                att.sign_with(&signing);
                write_envelope(&mut stream, &Envelope::SubmitAttestation(att))?;
                println!("[agent {id}] attestation submitted");
            }
            Envelope::Shutdown => {
                println!("[agent {id}] shutdown received");
                break;
            }
            other => {
                eprintln!("[agent {id}] unexpected envelope: {other:?}");
            }
        }
    }
    Ok(())
}

fn arg_or(args: &[String], flag: &str, default: &str) -> String {
    if let Some(pos) = args.iter().position(|a| a == flag) {
        if let Some(v) = args.get(pos + 1) {
            return v.clone();
        }
    }
    default.to_string()
}

fn u64_to_uuid(id: u64) -> [u8; 16] {
    let mut out = [0_u8; 16];
    out[..8].copy_from_slice(&id.to_le_bytes());
    out
}
