//! CosaCI coordinator — accepts agent registrations over mTLS, then runs
//! a persistent job loop: VRF-style assignment + quorum aggregation +
//! Merkle anchoring per job. Reuses agent connections across jobs and
//! drains gracefully on SIGINT/SIGTERM.
//!
//! Run with `cargo run --bin coordinator -- --addr 127.0.0.1:7878
//!                                          --ca /path/ca.pem
//!                                          --cert /path/server.pem
//!                                          --key  /path/server.key.pem
//!                                          --fleet 5 --committee 3
//!                                          --max-jobs 3`.

use std::collections::HashMap;
use std::env;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rustls::{ServerConfig, ServerConnection, StreamOwned};

use cosaci_core::attestation::AttestationResult;
use cosaci_core::merkle_log::MerkleLog;
use cosaci_core::quorum::{Outcome, RunnerId, StakeMap, Vote, VoteResult, Weight, aggregate};
use cosaci_core::signing::VerifyingKey;
use cosaci_protocol::proto::{Envelope, read_envelope, write_envelope};
use cosaci_protocol::tls::{install_crypto_provider, server_config_from_paths};

type ServerStream = StreamOwned<ServerConnection, TcpStream>;

struct RegisteredAgent {
    runner_id: RunnerId,
    stream: ServerStream,
    signing_pk: VerifyingKey,
    vrf_pk: [u8; 32],
    stake: u64,
}

fn main() -> std::io::Result<()> {
    install_crypto_provider();

    let args: Vec<String> = env::args().collect();
    let addr = arg_or(&args, "--addr", "127.0.0.1:7878");
    let ca_path = arg_or(&args, "--ca", "ca.pem");
    let cert_path = arg_or(&args, "--cert", "server.pem");
    let key_path = arg_or(&args, "--key", "server.key.pem");
    let fleet: u64 = arg_or(&args, "--fleet", "5").parse().expect("fleet u64");
    let committee_size: usize = arg_or(&args, "--committee", "3")
        .parse()
        .expect("committee usize");
    let job_a: i32 = arg_or(&args, "--a", "21").parse().expect("a i32");
    let job_b: i32 = arg_or(&args, "--b", "21").parse().expect("b i32");
    let max_jobs: u64 = arg_or(&args, "--max-jobs", &u64::MAX.to_string())
        .parse()
        .expect("max-jobs u64");

    // ── Drain flag set by SIGINT/SIGTERM ───────────────────────────────────
    // Once flipped: finish the in-flight job, decline new ones, send
    // Shutdown to all agents, exit.
    let draining = Arc::new(AtomicBool::new(false));
    install_signal_handlers(draining.clone())?;

    let server_cfg: Arc<ServerConfig> =
        server_config_from_paths(&ca_path, &cert_path, &key_path)
            .map_err(|e| std::io::Error::other(format!("server config: {e}")))?;

    println!("[coordinator] listening on {addr} (mTLS)");
    let listener = TcpListener::bind(&addr)?;

    // ── Phase 1: accept `fleet` mTLS connections + Register envelopes ──────
    // Connections established here are reused for every subsequent job.
    let mut agents = accept_fleet(&listener, &server_cfg, fleet)?;
    let stake_map: StakeMap = agents.iter().map(|a| (a.runner_id, a.stake)).collect();
    println!("[coordinator] fleet assembled ({} agents)", agents.len());

    // ── Phase 2: persistent job loop ───────────────────────────────────────
    // Each iteration is one (assign → collect → aggregate → anchor) cycle.
    // Per-job state lives entirely inside the loop body; no leaks across
    // jobs. The Merkle log is the only piece of state that accrues.
    let mut log = MerkleLog::new();
    let mut completed: u64 = 0;

    while completed < max_jobs && !draining.load(Ordering::Relaxed) {
        let job_id = completed + 1;
        match run_one_job(
            job_id,
            committee_size,
            job_a,
            job_b,
            &mut agents,
            &stake_map,
            &mut log,
        ) {
            Ok(()) => {
                completed += 1;
            }
            Err(e) => {
                eprintln!("[coordinator] job {job_id} aborted: {e}");
                // A per-job failure shouldn't poison the whole loop; the
                // committee may have a transient issue. Move on.
                completed += 1;
            }
        }
    }

    if draining.load(Ordering::Relaxed) {
        println!("[coordinator] draining (signal received), shutting down agents");
    } else {
        println!("[coordinator] reached max-jobs={max_jobs}, shutting down agents");
    }

    // ── Phase 3: graceful agent shutdown ───────────────────────────────────
    for a in agents.iter_mut() {
        let _ = write_envelope(&mut a.stream, &Envelope::Shutdown);
        let _ = a.stream.sock.shutdown(std::net::Shutdown::Both);
    }
    println!("[coordinator] done — completed {completed} job(s)");
    Ok(())
}

// ────────────────────────────────────────────────────────────────────────
// Job lifecycle
// ────────────────────────────────────────────────────────────────────────

fn accept_fleet(
    listener: &TcpListener,
    server_cfg: &Arc<ServerConfig>,
    fleet: u64,
) -> std::io::Result<Vec<RegisteredAgent>> {
    let mut agents: Vec<RegisteredAgent> = Vec::with_capacity(fleet as usize);
    while agents.len() < fleet as usize {
        let (tcp, peer) = listener.accept()?;
        tcp.set_nodelay(true)?;
        let conn = match ServerConnection::new(server_cfg.clone()) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[coordinator] ServerConnection::new for {peer}: {e}");
                continue;
            }
        };
        let mut stream = ServerStream::new(conn, tcp);

        let env = match read_envelope(&mut stream) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("[coordinator] handshake/read failed for {peer}: {e}");
                continue;
            }
        };
        let Envelope::Register {
            runner_id,
            signing_pubkey,
            vrf_pubkey,
            stake,
        } = env
        else {
            eprintln!("[coordinator] dropping non-Register from {peer}");
            continue;
        };
        let signing_pk = match VerifyingKey::from_bytes(&signing_pubkey) {
            Ok(pk) => pk,
            Err(e) => {
                eprintln!("[coordinator] bad pubkey from {peer}: {e}");
                continue;
            }
        };
        if let Err(e) = write_envelope(&mut stream, &Envelope::RegisterAck) {
            eprintln!("[coordinator] ack write failed for {peer}: {e}");
            continue;
        }
        println!(
            "[coordinator] registered runner {} from {} (stake {}, mTLS ✓)",
            runner_id, peer, stake
        );
        agents.push(RegisteredAgent {
            runner_id,
            stream,
            signing_pk,
            vrf_pk: vrf_pubkey,
            stake,
        });
    }
    Ok(agents)
}

fn run_one_job(
    job_id: u64,
    committee_size: usize,
    a: i32,
    b: i32,
    agents: &mut [RegisteredAgent],
    stake_map: &StakeMap,
    log: &mut MerkleLog,
) -> std::io::Result<()> {
    let job_seed = job_seed_bytes(job_id);
    let committee = select_committee_by_pubkey_hash(agents, &job_seed, committee_size);
    println!("[coordinator] job {job_id} committee: {committee:?}");

    // ── Broadcast Assign ───────────────────────────────────────────────
    let deadline = now_unix_ns() + 60_000_000_000;
    for ag in agents.iter_mut() {
        if committee.contains(&ag.runner_id) {
            write_envelope(
                &mut ag.stream,
                &Envelope::Assign {
                    job_id,
                    a,
                    b,
                    deadline_unix_ns: deadline,
                },
            )?;
        }
    }

    // ── Collect SubmitAttestation ──────────────────────────────────────
    let mut attestations = Vec::with_capacity(committee.len());
    for ag in agents.iter_mut() {
        if !committee.contains(&ag.runner_id) {
            continue;
        }
        let env = read_envelope(&mut ag.stream)?;
        let Envelope::SubmitAttestation(att) = env else {
            eprintln!(
                "[coordinator] runner {} returned {:?}, expected SubmitAttestation",
                ag.runner_id, env
            );
            continue;
        };
        let sig_ok = att.verify_signature(&ag.signing_pk);
        println!(
            "[coordinator] job {} runner {} attestation sig={} artifact={:02x?}…",
            job_id,
            ag.runner_id,
            if sig_ok { "ok" } else { "BAD" },
            &att.artifact_hash[..4]
        );
        if sig_ok {
            attestations.push(att);
        }
    }

    // ── Aggregate ──────────────────────────────────────────────────────
    let mut artifact_counts: HashMap<[u8; 32], u32> = HashMap::new();
    let votes: Vec<Vote> = attestations
        .iter()
        .map(|att| {
            *artifact_counts.entry(att.artifact_hash).or_insert(0) += 1;
            Vote {
                runner_id: att.runner_id,
                result: match att.result {
                    AttestationResult::Pass => VoteResult::Pass,
                    AttestationResult::Fail => VoteResult::Fail,
                },
            }
        })
        .collect();
    let committee_stake: Weight = committee
        .iter()
        .map(|id| stake_map.get(id).copied().unwrap_or(0))
        .sum();
    let threshold = (committee_stake * 2).div_ceil(3);
    let outcome = aggregate(&votes, threshold, stake_map);
    let consensus_artifact = artifact_counts
        .iter()
        .max_by_key(|&(_, c)| *c)
        .map(|(k, _)| *k)
        .unwrap_or([0_u8; 32]);
    println!(
        "[coordinator] job {} outcome {:?} (threshold {}, committee stake {})",
        job_id, outcome, threshold, committee_stake
    );

    if outcome == Outcome::Pass {
        let pos = log.append(consensus_artifact);
        let root = log.root().expect("nonempty");
        println!(
            "[coordinator] job {} anchored at position {} root {:02x?}…",
            job_id,
            pos,
            &root[..8]
        );
    }
    Ok(())
}

// ────────────────────────────────────────────────────────────────────────
// Signal handling
// ────────────────────────────────────────────────────────────────────────

fn install_signal_handlers(draining: Arc<AtomicBool>) -> std::io::Result<()> {
    use signal_hook::consts::{SIGINT, SIGTERM};
    use signal_hook::flag;
    flag::register(SIGINT, draining.clone())?;
    flag::register(SIGTERM, draining)?;
    Ok(())
}

// ────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────

fn arg_or(args: &[String], flag: &str, default: &str) -> String {
    if let Some(pos) = args.iter().position(|a| a == flag)
        && let Some(v) = args.get(pos + 1)
    {
        return v.clone();
    }
    default.to_string()
}

fn job_seed_bytes(job_id: u64) -> [u8; 32] {
    let mut seed = [0_u8; 32];
    seed[..8].copy_from_slice(&job_id.to_le_bytes());
    seed[31] = 0xab;
    seed
}

fn now_unix_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

fn select_committee_by_pubkey_hash(
    agents: &[RegisteredAgent],
    seed: &[u8; 32],
    k: usize,
) -> Vec<RunnerId> {
    use sha2::{Digest, Sha256};
    let mut scored: Vec<(RunnerId, [u8; 32])> = agents
        .iter()
        .map(|ag| {
            let mut h = Sha256::new();
            h.update(ag.vrf_pk);
            h.update(seed);
            let digest: [u8; 32] = h.finalize().into();
            (ag.runner_id, digest)
        })
        .collect();
    scored.sort_by(|a, b| a.1.cmp(&b.1));
    scored.into_iter().take(k).map(|(id, _)| id).collect()
}
