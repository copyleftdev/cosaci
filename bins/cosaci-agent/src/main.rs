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

use cosaci_core::attestation::{Attestation, AttestationResult};
use cosaci_core::capabilities::{Capabilities, Platform, Runtime};
use cosaci_core::quorum::RunnerId;
use cosaci_core::signing::Keypair;
use cosaci_protocol::proto::{Envelope, VRF_REGISTRATION_CHALLENGE, read_envelope, write_envelope};
use cosaci_protocol::tls::{client_config_from_paths, install_crypto_provider};
use cosaci_vrf::vrf::VrfKeypair;

type ClientStream = StreamOwned<ClientConnection, TcpStream>;

fn main() -> std::io::Result<()> {
    init_tracing();
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

    tracing::info!("[agent {id}] connecting to {addr} (mTLS)");
    let tcp = TcpStream::connect(&addr)?;
    tcp.set_nodelay(true)?;
    let server_name: ServerName<'static> = ServerName::try_from(server_name_str.clone())
        .map_err(|e| std::io::Error::other(format!("server name: {e}")))?;
    let conn = ClientConnection::new(client_cfg, server_name)
        .map_err(|e| std::io::Error::other(format!("ClientConnection::new: {e}")))?;
    let mut stream: ClientStream = ClientStream::new(conn, tcp);

    // Register — produce a VRF proof of possession for the fixed
    // registration challenge so the coordinator can verify we own the
    // claimed VRF pubkey before counting our stake. Capabilities are
    // declared at the same time so the coordinator can filter
    // committee candidates by job requirements (issue #34).
    let (reg_vrf_output, reg_vrf_proof) = vrf.evaluate(VRF_REGISTRATION_CHALLENGE);
    let capabilities = Capabilities {
        cpu: 4,
        memory_mb: 4096,
        platform: Platform::LinuxX86_64,
        runtimes: [Runtime::Wasm].into_iter().collect(),
    };
    write_envelope(
        &mut stream,
        &Envelope::Register {
            runner_id,
            signing_pubkey: signing_pk,
            vrf_pubkey: vrf_pk,
            vrf_output: reg_vrf_output,
            vrf_proof: reg_vrf_proof,
            stake,
            capabilities,
        },
    )?;
    match read_envelope(&mut stream)? {
        Envelope::RegisterAck => tracing::info!("[agent {id}] registered (mTLS ✓, VRF ✓)"),
        other => {
            tracing::warn!("[agent {id}] expected RegisterAck, got {other:?}");
            return Ok(());
        }
    }

    // Main loop
    loop {
        let env = match read_envelope(&mut stream) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!("[agent {id}] stream closed: {e}");
                break;
            }
        };
        match env {
            Envelope::JobSeed { job_id, seed } => {
                // Coordinator wants every fleet member's VRF output for
                // this seed before it picks the committee. Reply with a
                // proof; coordinator will verify before counting us.
                let (output, proof) = vrf.evaluate(&seed);
                write_envelope(
                    &mut stream,
                    &Envelope::VrfClaim {
                        job_id,
                        vrf_output: output,
                        vrf_proof: proof,
                    },
                )?;
            }
            Envelope::Assign {
                job_id,
                pipeline,
                requirements: _,
                deadline_unix_ns,
            } => {
                tracing::info!(
                    "[agent {id}] assigned job {job_id}: pipeline ({} step(s))",
                    pipeline.steps.len()
                );
                let result = cosaci_jobs::execute_pipeline(&pipeline)
                    .map_err(|e| std::io::Error::other(format!("pipeline: {e:?}")))?;
                let mut att = Attestation {
                    version: Attestation::VERSION,
                    job_id: u64_to_uuid(job_id),
                    commit: [0x42; 32],
                    runner_id,
                    result: AttestationResult::Pass,
                    environment_hash: [0xee; 32],
                    artifact_hash: result.final_artifact_hash,
                    timestamp_unix_ns: deadline_unix_ns,
                    signature: [0_u8; 64],
                };
                att.sign_with(&signing);
                write_envelope(&mut stream, &Envelope::SubmitAttestation(att))?;
                tracing::info!("[agent {id}] attestation submitted");
            }
            Envelope::Shutdown => {
                tracing::info!("[agent {id}] shutdown received");
                break;
            }
            other => {
                tracing::warn!("[agent {id}] unexpected envelope: {other:?}");
            }
        }
    }
    Ok(())
}

/// Structured logging via `tracing-subscriber` (issue #47, partial).
/// `RUST_LOG` controls verbosity (`RUST_LOG=agent=debug`); default
/// is `info`. Writes to stderr so coord/demo log forwarding still
/// captures it.
fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};
    let _ = fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(true)
        .with_writer(std::io::stderr)
        .try_init();
}

fn arg_or(args: &[String], flag: &str, default: &str) -> String {
    if let Some(pos) = args.iter().position(|a| a == flag)
        && let Some(v) = args.get(pos + 1)
    {
        return v.clone();
    }
    default.to_string()
}

fn u64_to_uuid(id: u64) -> [u8; 16] {
    let mut out = [0_u8; 16];
    out[..8].copy_from_slice(&id.to_le_bytes());
    out
}
