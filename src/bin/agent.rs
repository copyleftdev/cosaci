//! CosaCI agent — connects to the coordinator over mTLS, registers,
//! executes assigned jobs in the WASM sandbox, and returns signed
//! attestations.
//!
//! Run with `cargo run --bin agent -- --id 0 --addr 127.0.0.1:7878
//!                                    --ca /path/ca.pem
//!                                    --cert /path/agent-0.pem
//!                                    --key  /path/agent-0.key.pem
//!                                    --server-name cosaci.local
//!                                    --stake 100`.

use std::env;
use std::net::TcpStream;
use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};

use cosaci::attestation::{Attestation, AttestationResult};
use cosaci::proto::{Envelope, read_envelope, write_envelope};
use cosaci::quorum::RunnerId;
use cosaci::signing::Keypair;
use cosaci::tls::{client_config_from_paths, install_crypto_provider};
use cosaci::vrf::VrfKeypair;
use cosaci::wasm_runtime::{execute_add, output_hash};

type ClientStream = StreamOwned<ClientConnection, TcpStream>;

fn main() -> std::io::Result<()> {
    install_crypto_provider();

    let args: Vec<String> = env::args().collect();
    let id: u64 = arg_or(&args, "--id", "0").parse().expect("id u64");
    let addr = arg_or(&args, "--addr", "127.0.0.1:7878");
    let ca_path = arg_or(&args, "--ca", "ca.pem");
    let cert_path = arg_or(&args, "--cert", "agent.pem");
    let key_path = arg_or(&args, "--key", "agent.key.pem");
    let server_name_str = arg_or(&args, "--server-name", "cosaci.local");
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

    let client_cfg: Arc<ClientConfig> =
        client_config_from_paths(&ca_path, &cert_path, &key_path)
            .map_err(|e| std::io::Error::other(format!("client config: {e}")))?;

    println!("[agent {id}] connecting to {addr} (mTLS)");
    let tcp = TcpStream::connect(&addr)?;
    tcp.set_nodelay(true)?;
    let server_name: ServerName<'static> = ServerName::try_from(server_name_str.clone())
        .map_err(|e| std::io::Error::other(format!("server name: {e}")))?;
    let conn = ClientConnection::new(client_cfg, server_name)
        .map_err(|e| std::io::Error::other(format!("ClientConnection::new: {e}")))?;
    let mut stream: ClientStream = ClientStream::new(conn, tcp);

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
    match read_envelope(&mut stream)? {
        Envelope::RegisterAck => println!("[agent {id}] registered (mTLS ✓)"),
        other => {
            eprintln!("[agent {id}] expected RegisterAck, got {other:?}");
            return Ok(());
        }
    }

    // Main loop
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
                let result =
                    execute_add(a, b).map_err(|e| std::io::Error::other(format!("wasm: {e}")))?;
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
