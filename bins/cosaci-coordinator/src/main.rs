//! CosaCI coordinator — accepts agent registrations over mTLS, then runs
//! a persistent job loop with **VRF-proof committee selection**: per
//! job, every fleet member submits a VRF output + proof on the job
//! seed; the coordinator verifies all proofs and picks the top-k by
//! lexicographically smallest output. Reuses agent connections across
//! jobs and drains gracefully on SIGINT/SIGTERM.
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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use rustls::{ServerConfig, ServerConnection, StreamOwned};

use cosaci_core::attestation::AttestationResult;
use cosaci_core::capabilities::{
    Candidate, Capabilities, JobRequirements, Platform, Runtime, select_capability_aware_committee,
};
use cosaci_core::merkle_log::{FileStore, MerkleLog};
use cosaci_core::quorum::{Outcome, RunnerId, StakeMap, Vote, VoteResult, Weight, aggregate};
use cosaci_core::signing::VerifyingKey;
use cosaci_protocol::proto::{Envelope, VRF_REGISTRATION_CHALLENGE, read_envelope, write_envelope};
use cosaci_protocol::tls::{install_crypto_provider, server_config_from_paths_with_crl};
use cosaci_vrf::vrf::verify as vrf_verify;
use cosaci_wasm::wasm_runtime::{canned_add_module, canned_mul_module, encode_args};

/// Atomic-swap holder for the current `ServerConfig`. SIGHUP triggers
/// a re-read of the cert/key/CRL paths and an atomic replacement here.
/// Existing TLS connections keep their own copy of the verifier and
/// are unaffected; only NEW `ServerConnection::new` calls pick up the
/// reload.
type SharedServerConfig = Arc<Mutex<Arc<ServerConfig>>>;

type ServerStream = StreamOwned<ServerConnection, TcpStream>;

struct RegisteredAgent {
    runner_id: RunnerId,
    stream: ServerStream,
    signing_pk: VerifyingKey,
    vrf_pk: [u8; 32],
    stake: u64,
    capabilities: Capabilities,
}

fn main() -> std::io::Result<()> {
    install_crypto_provider();

    let args: Vec<String> = env::args().collect();
    let addr = arg_or(&args, "--addr", "127.0.0.1:7878");
    let ca_path = arg_or(&args, "--ca", "ca.pem");
    let cert_path = arg_or(&args, "--cert", "server.pem");
    let key_path = arg_or(&args, "--key", "server.key.pem");
    // `--crl <path>` is optional. A missing path is treated as "no
    // revocations". SIGHUP rereads this same path, so an operator can
    // hot-add revocations by writing the file and signaling the coord.
    let crl_path = arg_or(&args, "--crl", "");
    let fleet: u64 = arg_or(&args, "--fleet", "5").parse().expect("fleet u64");
    let committee_size: usize = arg_or(&args, "--committee", "3")
        .parse()
        .expect("committee usize");
    let job_a: i32 = arg_or(&args, "--a", "21").parse().expect("a i32");
    let job_b: i32 = arg_or(&args, "--b", "21").parse().expect("b i32");
    let max_jobs: u64 = arg_or(&args, "--max-jobs", &u64::MAX.to_string())
        .parse()
        .expect("max-jobs u64");
    // `--log <path>` selects the file-backed Merkle log (issue #33).
    // Empty (default) means in-memory: the log is reset on every start.
    // A non-empty path opens (or creates) that file as an append-only
    // 32-bytes-per-entry log; restart recovers prior anchors.
    let log_path = arg_or(&args, "--log", "");

    // ── Drain flag set by SIGINT/SIGTERM ───────────────────────────────────
    let draining = Arc::new(AtomicBool::new(false));
    install_signal_handlers(draining.clone())?;

    // Initial server config; will be hot-swappable via SIGHUP.
    let initial_cfg = build_server_config(&ca_path, &cert_path, &key_path, &crl_path)?;
    let shared_cfg: SharedServerConfig = Arc::new(Mutex::new(initial_cfg));
    install_sighup_reloader(
        shared_cfg.clone(),
        ca_path.clone(),
        cert_path.clone(),
        key_path.clone(),
        crl_path.clone(),
    )?;

    println!("[coordinator] listening on {addr} (mTLS)");
    let listener = TcpListener::bind(&addr)?;

    // ── Phase 1: accept fleet + verify registration VRF proofs ─────────────
    let mut agents = accept_fleet(&listener, &shared_cfg, fleet)?;
    let stake_map: StakeMap = agents.iter().map(|a| (a.runner_id, a.stake)).collect();
    println!(
        "[coordinator] fleet assembled ({} agents, all VRF-attested)",
        agents.len()
    );

    // Pre-compile both canned modules and alternate per job. Each job
    // ships a single-step `ExecWasm` pipeline; future job submissions
    // (#32) will let external clients ship their own pipelines.
    let add_wasm = canned_add_module().expect("canned add module");
    let mul_wasm = canned_mul_module().expect("canned mul module");

    // Demo job requirements: every agent the demo spawns satisfies
    // these (Linux x86_64 + Wasm). Future job submissions (#32) will
    // ship per-job requirements; for now the value is uniform.
    let demo_requirements = JobRequirements {
        cpu: 1,
        memory_mb: 256,
        platform: Platform::LinuxX86_64,
        runtimes: [Runtime::Wasm].into_iter().collect(),
    };

    // ── Phase 2: persistent job loop ───────────────────────────────────────
    let mut log = if log_path.is_empty() {
        LogBackend::Mem(MerkleLog::new())
    } else {
        let file_log = MerkleLog::<FileStore>::open(&log_path)?;
        println!(
            "[coordinator] Merkle log path: {log_path} ({} entries on disk)",
            file_log.len()
        );
        LogBackend::File(file_log)
    };
    let mut completed: u64 = 0;

    while completed < max_jobs && !draining.load(Ordering::Relaxed) {
        let job_id = completed + 1;
        let module = if job_id % 2 == 1 {
            &add_wasm
        } else {
            &mul_wasm
        };
        let args = encode_args(job_a, job_b).expect("encode args");
        let pipeline = cosaci_jobs::Pipeline {
            steps: vec![cosaci_jobs::Step::ExecWasm {
                module: module.clone(),
                args_cbor: args,
                limits: cosaci_jobs::Limits::default(),
            }],
        };
        match run_one_job(
            job_id,
            committee_size,
            pipeline,
            demo_requirements.clone(),
            module,
            &mut agents,
            &stake_map,
            &mut log,
        ) {
            Ok(()) => {
                completed += 1;
            }
            Err(e) => {
                eprintln!("[coordinator] job {job_id} aborted: {e}");
                completed += 1;
            }
        }
    }

    if draining.load(Ordering::Relaxed) {
        println!("[coordinator] draining (signal received), shutting down agents");
    } else {
        println!("[coordinator] reached max-jobs={max_jobs}, shutting down agents");
    }

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
    shared_cfg: &SharedServerConfig,
    fleet: u64,
) -> std::io::Result<Vec<RegisteredAgent>> {
    let mut agents: Vec<RegisteredAgent> = Vec::with_capacity(fleet as usize);
    while agents.len() < fleet as usize {
        let (tcp, peer) = listener.accept()?;
        tcp.set_nodelay(true)?;
        // Snapshot the current config — picks up SIGHUP-driven swaps
        // for new connections without affecting any already established.
        let cfg_snapshot = shared_cfg.lock().expect("shared cfg poisoned").clone();
        let conn = match ServerConnection::new(cfg_snapshot) {
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
            vrf_output,
            vrf_proof,
            stake,
            capabilities,
        } = env
        else {
            eprintln!("[coordinator] dropping non-Register from {peer}");
            continue;
        };

        // Verify the registration VRF proof — agent must own the secret
        // key for the claimed VRF pubkey.
        if let Err(e) = vrf_verify(
            &vrf_pubkey,
            VRF_REGISTRATION_CHALLENGE,
            &vrf_output,
            &vrf_proof,
        ) {
            eprintln!("[coordinator] dropping {peer}: registration VRF proof rejected ({e:?})");
            continue;
        }

        let signing_pk = match VerifyingKey::from_bytes(&signing_pubkey) {
            Ok(pk) => pk,
            Err(e) => {
                eprintln!("[coordinator] bad signing pubkey from {peer}: {e}");
                continue;
            }
        };
        if let Err(e) = write_envelope(&mut stream, &Envelope::RegisterAck) {
            eprintln!("[coordinator] ack write failed for {peer}: {e}");
            continue;
        }
        println!(
            "[coordinator] registered runner {} from {} (stake {}, mTLS ✓, VRF ✓, platform={:?}, runtimes={:?})",
            runner_id, peer, stake, capabilities.platform, capabilities.runtimes
        );
        agents.push(RegisteredAgent {
            runner_id,
            stream,
            signing_pk,
            vrf_pk: vrf_pubkey,
            stake,
            capabilities,
        });
    }
    Ok(agents)
}

fn run_one_job(
    job_id: u64,
    committee_size: usize,
    pipeline: cosaci_jobs::Pipeline,
    requirements: JobRequirements,
    log_module: &[u8],
    agents: &mut [RegisteredAgent],
    stake_map: &StakeMap,
    log: &mut LogBackend,
) -> std::io::Result<()> {
    let job_seed = job_seed_bytes(job_id);
    // log_module is the leading WASM module bytes — used only for the
    // human-readable hash prefix in the log line. Once jobs carry
    // arbitrary pipelines the log line should switch to the pipeline's
    // canonical hash.
    let mh = cosaci_wasm::wasm_runtime::module_hash(log_module);

    // ── Phase 2a: VRF round — ask every agent for VRF(job_seed) ────────
    // The committee is chosen by the actual VRF outputs, not by hashing
    // the public keys. Coord verifies every proof before counting.
    for ag in agents.iter_mut() {
        write_envelope(
            &mut ag.stream,
            &Envelope::JobSeed {
                job_id,
                seed: job_seed,
            },
        )?;
    }

    // Collect every fleet member's VrfClaim, in the order we sent
    // JobSeed (each connection is a synchronous request/response).
    let mut claims: Vec<(RunnerId, [u8; 32])> = Vec::with_capacity(agents.len());
    for ag in agents.iter_mut() {
        let env = read_envelope(&mut ag.stream)?;
        let Envelope::VrfClaim {
            job_id: claim_job_id,
            vrf_output,
            vrf_proof,
        } = env
        else {
            eprintln!(
                "[coordinator] runner {} returned {:?}, expected VrfClaim",
                ag.runner_id, env
            );
            continue;
        };
        if claim_job_id != job_id {
            eprintln!(
                "[coordinator] runner {} VrfClaim job_id mismatch ({} != {})",
                ag.runner_id, claim_job_id, job_id
            );
            continue;
        }
        if let Err(e) = vrf_verify(&ag.vrf_pk, &job_seed, &vrf_output, &vrf_proof) {
            eprintln!(
                "[coordinator] runner {} VrfClaim proof rejected ({:?}); excluding from selection",
                ag.runner_id, e
            );
            continue;
        }
        claims.push((ag.runner_id, vrf_output));
    }

    // ── Phase 2b: build candidate list + filter-then-rank ──────────────
    // Issue #34: only runners whose `Capabilities` satisfy the job's
    // `JobRequirements` are eligible for the committee. The pure
    // selection logic lives in `cosaci-core::capabilities`; the
    // coordinator's job here is to assemble the candidate list from
    // the VRF round's claims and the registry's capability records.
    let agent_caps: HashMap<RunnerId, Capabilities> = agents
        .iter()
        .map(|a| (a.runner_id, a.capabilities.clone()))
        .collect();
    let candidates: Vec<Candidate<RunnerId>> = claims
        .into_iter()
        .filter_map(|(id, vrf_output)| {
            agent_caps.get(&id).map(|caps| Candidate {
                id,
                capabilities: caps.clone(),
                vrf_output,
            })
        })
        .collect();

    let Some(committee) =
        select_capability_aware_committee(&candidates, &requirements, committee_size)
    else {
        let eligible_count = candidates
            .iter()
            .filter(|c| cosaci_core::capabilities::matches(&c.capabilities, &requirements))
            .count();
        eprintln!(
            "[coordinator] job {job_id} ABORTED: only {eligible_count} of {} runner(s) match requirements ({:?} / {} cpu / {} MiB / runtimes {:?}); need {committee_size}",
            candidates.len(),
            requirements.platform,
            requirements.cpu,
            requirements.memory_mb,
            requirements.runtimes
        );
        return Ok(());
    };
    println!(
        "[coordinator] job {job_id} committee: {committee:?} module={:02x?}… ({} bytes), pipeline ({} step(s))",
        &mh[..4],
        log_module.len(),
        pipeline.steps.len()
    );

    // ── Phase 2c: broadcast Assign to committee ────────────────────────
    let deadline = now_unix_ns() + 60_000_000_000;
    for ag in agents.iter_mut() {
        if committee.contains(&ag.runner_id) {
            write_envelope(
                &mut ag.stream,
                &Envelope::Assign {
                    job_id,
                    pipeline: pipeline.clone(),
                    requirements: requirements.clone(),
                    deadline_unix_ns: deadline,
                },
            )?;
        }
    }

    // ── Phase 2d: collect SubmitAttestation ────────────────────────────
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

    // ── Phase 2e: aggregate ────────────────────────────────────────────
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
        let pos = log.append(consensus_artifact)?;
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

/// Spawn a thread that blocks on SIGHUP and, on each signal, re-reads
/// the cert/key/CRL paths and atomically swaps the shared config.
/// Existing connections retain the old verifier (rustls copies what
/// it needs at connection construction time); only new
/// `ServerConnection::new` calls pick up the rotation.
fn install_sighup_reloader(
    shared_cfg: SharedServerConfig,
    ca_path: String,
    cert_path: String,
    key_path: String,
    crl_path: String,
) -> std::io::Result<()> {
    use signal_hook::consts::SIGHUP;
    use signal_hook::iterator::Signals;

    let mut signals = Signals::new([SIGHUP])?;
    thread::spawn(move || {
        for _sig in signals.forever() {
            match build_server_config(&ca_path, &cert_path, &key_path, &crl_path) {
                Ok(new_cfg) => {
                    *shared_cfg.lock().expect("shared cfg poisoned") = new_cfg;
                    eprintln!(
                        "[coordinator] SIGHUP: server config reloaded (cert={cert_path}, crl={})",
                        if crl_path.is_empty() {
                            "<none>"
                        } else {
                            crl_path.as_str()
                        }
                    );
                }
                Err(e) => {
                    eprintln!("[coordinator] SIGHUP: reload failed ({e}); keeping previous config");
                }
            }
        }
    });
    Ok(())
}

fn build_server_config(
    ca_path: &str,
    cert_path: &str,
    key_path: &str,
    crl_path: &str,
) -> std::io::Result<Arc<ServerConfig>> {
    let crl_arg: Option<&str> = if crl_path.is_empty() {
        None
    } else {
        Some(crl_path)
    };
    server_config_from_paths_with_crl(ca_path, cert_path, key_path, crl_arg)
        .map_err(|e| std::io::Error::other(format!("server config: {e}")))
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

/// Enum-dispatched Merkle log backend. The coordinator's caller picks
/// at startup based on `--log <path>`; the rest of the loop is
/// agnostic. Both arms expose the same `(append, root)` surface the
/// coordinator needs.
enum LogBackend {
    Mem(MerkleLog),
    File(MerkleLog<FileStore>),
}

impl LogBackend {
    fn append(&mut self, entry: cosaci_core::merkle_log::Hash) -> std::io::Result<u64> {
        match self {
            Self::Mem(l) => Ok(l.append(entry)),
            Self::File(l) => l.append(entry),
        }
    }

    fn root(&self) -> Option<cosaci_core::merkle_log::Hash> {
        match self {
            Self::Mem(l) => l.root(),
            Self::File(l) => l.root(),
        }
    }
}
