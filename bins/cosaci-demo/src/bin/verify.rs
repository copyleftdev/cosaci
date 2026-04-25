//! CosaCI verifier — connects to the coordinator's read API over mTLS,
//! retrieves a `(JobBundle, LogRoot)` for the requested job, and runs
//! `verify_inclusion` against it. Exits 0 on a verifying bundle, 1 on
//! a missing or tampered bundle.
//!
//! This is the smoke-test client for issue #44; production auditors
//! would speak the same wire protocol with their own tooling.
//!
//! Run with:
//!
//! ```text
//! cargo run --bin verify -- \
//!     --addr 127.0.0.1:7879 \
//!     --ca   /path/ca.pem \
//!     --cert /path/auditor.pem \
//!     --key  /path/auditor.key.pem \
//!     --server-name cosaci.local \
//!     --job-id 1
//! ```
//!
//! Each request opens a fresh connection — the coordinator's read
//! server handles one envelope per accept.

use std::env;
use std::net::TcpStream;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};

use cosaci_core::merkle_log::verify_inclusion;
use cosaci_protocol::proto::{Envelope, read_envelope, write_envelope};
use cosaci_protocol::tls::{client_config_from_paths, install_crypto_provider};

type ClientStream = StreamOwned<ClientConnection, TcpStream>;

fn main() -> std::io::Result<()> {
    install_crypto_provider();

    let args: Vec<String> = env::args().collect();
    let addr = arg_or(&args, "--addr", "127.0.0.1:7879");
    let ca_path = arg_or(&args, "--ca", "ca.pem");
    let cert_path = arg_or(&args, "--cert", "auditor.pem");
    let key_path = arg_or(&args, "--key", "auditor.key.pem");
    let server_name_str = arg_or(&args, "--server-name", "cosaci.local");
    let job_id: u64 = arg_or(&args, "--job-id", "1").parse().expect("job-id u64");
    let max_attempts: u32 = arg_or(&args, "--max-attempts", "30")
        .parse()
        .expect("max-attempts u32");
    let backoff_ms: u64 = arg_or(&args, "--backoff-ms", "200")
        .parse()
        .expect("backoff-ms u64");

    let client_cfg: Arc<ClientConfig> =
        client_config_from_paths(&ca_path, &cert_path, &key_path)
            .map_err(|e| std::io::Error::other(format!("client config: {e}")))?;
    let server_name: ServerName<'static> = ServerName::try_from(server_name_str.clone())
        .map_err(|e| std::io::Error::other(format!("server name: {e}")))?;

    println!("[verify] requesting job {job_id} from {addr}");

    // Retry GetJob until the coord has anchored it (or until we
    // exhaust attempts). Coords commit asynchronously to the read
    // path, so an external client typically polls on a short backoff.
    let bundle = loop_request_bundle(
        &addr,
        &client_cfg,
        &server_name,
        job_id,
        max_attempts,
        backoff_ms,
    )?;

    // Sanity: the bundle's internal pointers all agree.
    assert_eq!(
        bundle.merkle_proof.entry, bundle.consensus_artifact,
        "bundle entry mismatch"
    );
    assert_eq!(
        bundle.merkle_proof.position, bundle.log_position,
        "bundle position mismatch"
    );
    assert_eq!(
        bundle.merkle_proof.length_at_proof, bundle.log_length_at_anchor,
        "bundle length mismatch"
    );

    // Cross-check: the latest log root is at least as long as the
    // bundle's frozen length (the log only grows).
    let (current_root, current_length) = request_log_root(&addr, &client_cfg, &server_name)?;
    println!(
        "[verify] log root {:02x?}… length {} (bundle frozen at length {})",
        &current_root.unwrap_or([0_u8; 32])[..8],
        current_length,
        bundle.log_length_at_anchor
    );
    assert!(
        current_length >= bundle.log_length_at_anchor,
        "log length shrank?"
    );

    // The actual proof check.
    let ok = verify_inclusion(&bundle.merkle_proof, bundle.log_root);
    if !ok {
        eprintln!("[verify] FAIL — verify_inclusion rejected the bundle");
        std::process::exit(1);
    }
    println!(
        "[verify] OK — job {job_id} anchored at position {} (root {:02x?}…), {} attestation(s)",
        bundle.log_position,
        &bundle.log_root[..8],
        bundle.committee_attestations.len()
    );
    Ok(())
}

fn loop_request_bundle(
    addr: &str,
    client_cfg: &Arc<ClientConfig>,
    server_name: &ServerName<'static>,
    job_id: u64,
    max_attempts: u32,
    backoff_ms: u64,
) -> std::io::Result<cosaci_core::retrieval::JobBundle> {
    for attempt in 1..=max_attempts {
        match request_job(addr, client_cfg, server_name, job_id) {
            Ok(Some(b)) => return Ok(b),
            Ok(None) => {
                if attempt < max_attempts {
                    thread::sleep(Duration::from_millis(backoff_ms));
                }
            }
            Err(e) => {
                eprintln!("[verify] attempt {attempt}: {e}");
                thread::sleep(Duration::from_millis(backoff_ms));
            }
        }
    }
    Err(std::io::Error::other(format!(
        "job {job_id} not committed within {max_attempts} attempts"
    )))
}

fn request_job(
    addr: &str,
    client_cfg: &Arc<ClientConfig>,
    server_name: &ServerName<'static>,
    job_id: u64,
) -> std::io::Result<Option<cosaci_core::retrieval::JobBundle>> {
    let mut stream = open_stream(addr, client_cfg, server_name)?;
    write_envelope(&mut stream, &Envelope::GetJob { job_id })?;
    match read_envelope(&mut stream)? {
        Envelope::JobBundleResponse(b) => Ok(Some(b)),
        Envelope::JobNotFound { .. } => Ok(None),
        other => Err(std::io::Error::other(format!(
            "unexpected response to GetJob: {other:?}"
        ))),
    }
}

fn request_log_root(
    addr: &str,
    client_cfg: &Arc<ClientConfig>,
    server_name: &ServerName<'static>,
) -> std::io::Result<(Option<[u8; 32]>, u64)> {
    let mut stream = open_stream(addr, client_cfg, server_name)?;
    write_envelope(&mut stream, &Envelope::GetLogRoot)?;
    match read_envelope(&mut stream)? {
        Envelope::LogRoot { root, length } => Ok((root, length)),
        other => Err(std::io::Error::other(format!(
            "unexpected response to GetLogRoot: {other:?}"
        ))),
    }
}

fn open_stream(
    addr: &str,
    client_cfg: &Arc<ClientConfig>,
    server_name: &ServerName<'static>,
) -> std::io::Result<ClientStream> {
    let tcp = TcpStream::connect(addr)?;
    tcp.set_nodelay(true)?;
    let conn = ClientConnection::new(client_cfg.clone(), server_name.clone())
        .map_err(|e| std::io::Error::other(format!("ClientConnection::new: {e}")))?;
    Ok(ClientStream::new(conn, tcp))
}

fn arg_or(args: &[String], flag: &str, default: &str) -> String {
    if let Some(pos) = args.iter().position(|a| a == flag)
        && let Some(v) = args.get(pos + 1)
    {
        return v.clone();
    }
    default.to_string()
}
