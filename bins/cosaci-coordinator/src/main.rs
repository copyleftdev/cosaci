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
use std::io::BufRead;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Deserialize;

use rustls::{ServerConfig, ServerConnection, StreamOwned};

use cosaci_core::attestation::AttestationResult;
use cosaci_core::capabilities::{
    Candidate, Capabilities, JobRequirements, Platform, Runtime, select_capability_aware_committee,
};
use cosaci_core::clock::SystemClock;
use cosaci_core::merkle_log::{FileStore, MerkleLog, hash_bytes};
use cosaci_core::quorum::{Outcome, RunnerId, Vote, VoteResult, Weight, aggregate};
use cosaci_core::retrieval::{JobRecord, build_bundle};
use cosaci_core::signing::VerifyingKey;
use cosaci_protocol::proto::{Envelope, VRF_REGISTRATION_CHALLENGE, read_envelope, write_envelope};
use cosaci_protocol::tls::{install_crypto_provider, server_config_from_paths_with_crl};
use cosaci_state::enrollment::{EnrollmentSet, fingerprint, fingerprint_hex};
use cosaci_state::journal::{Journal, JournalEntry, JournalOutcome, reconstruct_state, replay};
use cosaci_state::rate_limit::RateLimiter;
use cosaci_state::stake_ledger::StakeLedger;
use cosaci_state::submission_auth::{AuthCheck, JobSubmissionPayload, verify_and_admit};
use cosaci_state::tenant::{TenantRegistry, parse_hex32};
use cosaci_vrf::vrf::verify as vrf_verify;
use cosaci_wasm::wasm_runtime::{canned_add_module, canned_mul_module, encode_args};

/// One job submission read from stdin (issue #32). NDJSON wire shape:
/// `{"kind":"add","a":1,"b":2}` (deadline_secs optional, defaults
/// to 60). v0.3 dispatches `kind` to a canned WASM module — once
/// the deterministic source-fetching step (#40) lands, submissions
/// will carry arbitrary module bytes + args_cbor + a pipeline.
///
/// Issue #46 added the auth fields (`tenant_id`, `nonce`, `pubkey_hex`,
/// `signature_hex`). They are optional at the wire level so legacy
/// submissions still parse, but the coord rejects auth-less
/// submissions when `--tenants <path>` was supplied at startup.
#[derive(Debug, Clone, Deserialize)]
struct JobSubmission {
    kind: JobKind,
    a: i32,
    b: i32,
    #[serde(default = "default_deadline_secs")]
    deadline_secs: u32,
    /// Tenant id (issue #46). Required when `--tenants` is set.
    #[serde(default)]
    tenant_id: Option<u64>,
    /// Replay-protection nonce (issue #46).
    #[serde(default)]
    nonce: Option<u128>,
    /// Lowercase-hex 32-byte ed25519 pubkey of the signer.
    #[serde(default)]
    pubkey_hex: Option<String>,
    /// Lowercase-hex 64-byte ed25519 signature over the canonical
    /// `JobSubmissionPayload` bytes.
    #[serde(default)]
    signature_hex: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum JobKind {
    Add,
    Mul,
}

impl JobKind {
    /// Wire-string form (matches the issue-#32 lowercase contract +
    /// the `serde(rename_all = "lowercase")` Deserialize derive).
    /// Used when reconstructing the canonical signing payload.
    fn as_wire(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Mul => "mul",
        }
    }
}

fn default_deadline_secs() -> u32 {
    60
}

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
    init_tracing();
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
    // `--runner-timeout-secs <s>` (issue #61) is the per-runner
    // attestation-read deadline. A runner that doesn't return a
    // SubmitAttestation within this window is recorded as missing
    // and the responding subset still aggregates to an outcome.
    // Default 30s — generous enough for slow CI workloads, tight
    // enough that wedged runners don't tank job latency forever.
    let runner_timeout_secs: u64 = arg_or(&args, "--runner-timeout-secs", "30")
        .parse()
        .expect("runner-timeout-secs u64");
    // `--log <path>` selects the file-backed Merkle log (issue #33).
    // Empty (default) means in-memory: the log is reset on every start.
    // A non-empty path opens (or creates) that file as an append-only
    // 32-bytes-per-entry log; restart recovers prior anchors.
    let log_path = arg_or(&args, "--log", "");
    // `--read-addr <addr>` enables the read API (issue #44). Empty
    // means disabled (no read server thread spawned). Non-empty:
    // bind a second TLS listener on that addr and serve `GetJob` /
    // `GetLogRoot` requests against the live job registry + log.
    let read_addr = arg_or(&args, "--read-addr", "");
    // `--enrollment <path>` enables the agent-enrollment gate
    // (issue #45). Empty means disabled — every mTLS-/VRF-valid
    // registration is accepted (current behavior). Non-empty: load
    // the enrollment file at startup and reject any agent whose
    // `(runner_id, signing_fp, vrf_fp)` triple isn't on the list.
    let enrollment_path = arg_or(&args, "--enrollment", "");
    // `--journal <path>` enables crash-recovery journaling
    // (issue #51). Empty means disabled — no journal writes. Non-
    // empty: append one NDJSON line per state transition with fsync.
    // On startup, the journal is replayed and the per-job-state
    // summary is logged for the operator. v0.3 doesn't yet re-run
    // pending jobs from the journal — that's a follow-on once #32
    // (job submission) carries the source-of-job into recovery.
    let journal_path = arg_or(&args, "--journal", "");
    // `--slash-fraction <f>` controls how much stake a runner loses
    // when their attestation diverges from the consensus artifact
    // (issue #35). Default 0.25 (== stake / 4 per the issue spec).
    // Clamped to [0.0, 1.0]; 0.0 disables slashing.
    let slash_fraction: f32 = arg_or(&args, "--slash-fraction", "0.25")
        .parse()
        .expect("slash-fraction f32");
    // `--submit-stdin` (issue #32): read NDJSON `JobSubmission`
    // records from stdin, push them to a bounded queue, and have
    // the job loop pull from the queue instead of round-robining
    // canned `add` / `mul`. Empty stdin = no jobs (coord exits
    // after fleet assembly). Closed stdin + drained queue = clean
    // shutdown. Default off preserves the legacy canned behavior.
    let submit_stdin = args.iter().any(|a| a == "--submit-stdin");
    // `--queue-cap N` (issue #32): bounded queue capacity for
    // stdin submissions. On overflow the reader logs a warning and
    // drops the record (reject-rather-than-block — the documented
    // backpressure policy). Default 64 — large enough to absorb a
    // burst of CI events, small enough to fail loudly under
    // sustained overload.
    let queue_cap: usize = arg_or(&args, "--queue-cap", "64")
        .parse()
        .expect("queue-cap usize");
    // `--tenants <path>` (issue #46): enable per-tenant signed
    // submissions. Empty (default) preserves the legacy unauthenticated
    // stdin path. Non-empty: load the tenant registry at startup,
    // verify every submission's signature, and rate-limit admission
    // per the tenant's configured token bucket.
    let tenants_path = arg_or(&args, "--tenants", "");

    let enrollment: Option<Arc<EnrollmentSet>> = if enrollment_path.is_empty() {
        None
    } else {
        let set = EnrollmentSet::load_from_path(&enrollment_path)?;
        tracing::info!(
            "[coordinator] enrollment gate enabled ({} runner(s) loaded from {})",
            set.len(),
            enrollment_path
        );
        Some(Arc::new(set))
    };

    // Crash-recovery journal (issue #51). Empty path = disabled.
    // Non-empty: replay first to discover any pre-crash state, log
    // a summary for the operator, then open the journal for
    // append. v0.3 logs the recovery summary but does NOT yet re-run
    // pending jobs (that requires #32's job-source-in-journal work).
    let journal: Option<Arc<Mutex<Journal>>> = if journal_path.is_empty() {
        None
    } else {
        let entries = replay(&journal_path)?;
        let state = reconstruct_state(&entries);
        let pending_run = state.pending_re_run();
        let pending_anchor = state.pending_re_anchor();
        let anchored_count = state.anchored_jobs().len();
        tracing::info!(
            "[coordinator] journal replayed from {}: {} entries, {} previously-anchored job(s), {} pending re-run, {} pending re-anchor",
            journal_path,
            entries.len(),
            anchored_count,
            pending_run.len(),
            pending_anchor.len()
        );
        if !pending_run.is_empty() {
            tracing::info!(
                "[coordinator] journal pending re-run job_ids: {:?} (NOT auto-rerun in v0.3 — see #32 + #51 follow-on)",
                pending_run
            );
        }
        if !pending_anchor.is_empty() {
            tracing::info!(
                "[coordinator] journal pending re-anchor job_ids: {:?} (NOT auto-anchored in v0.3 — operator triage)",
                pending_anchor
            );
        }
        Some(Arc::new(Mutex::new(Journal::open(&journal_path)?)))
    };

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

    tracing::info!("[coordinator] listening on {addr} (mTLS)");
    let listener = TcpListener::bind(&addr)?;

    // ── Phase 1: accept fleet + verify registration VRF proofs ─────────────
    let mut agents = accept_fleet(&listener, &shared_cfg, fleet, enrollment.as_deref())?;
    // Stake ledger (issue #35): seeded from registration-time stakes,
    // mutated as the job loop slashes minority disagreers. The
    // quorum threshold is computed against the current ledger state,
    // so a slashed runner's voting weight shrinks immediately.
    let mut stake_ledger =
        StakeLedger::from_stake_map(agents.iter().map(|a| (a.runner_id, a.stake)).collect());
    tracing::info!(
        "[coordinator] fleet assembled ({} agents, all VRF-attested, slash_fraction={})",
        agents.len(),
        slash_fraction
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
    let log_backend = if log_path.is_empty() {
        LogBackend::Mem(MerkleLog::new())
    } else {
        let file_log = MerkleLog::<FileStore>::open(&log_path)?;
        tracing::info!(
            "[coordinator] Merkle log path: {log_path} ({} entries on disk)",
            file_log.len()
        );
        LogBackend::File(file_log)
    };
    let log: Arc<Mutex<LogBackend>> = Arc::new(Mutex::new(log_backend));
    let records: Arc<Mutex<HashMap<u64, JobRecord>>> = Arc::new(Mutex::new(HashMap::new()));

    // Read API (issue #44) — only spawn the listener if --read-addr
    // was given. Daemon thread; dies when the process exits.
    if !read_addr.is_empty() {
        spawn_read_server(
            read_addr.clone(),
            shared_cfg.clone(),
            records.clone(),
            log.clone(),
        )?;
        tracing::info!("[coordinator] read API listening on {read_addr} (mTLS)");
    }

    // Tenant registry + rate limiter (issue #46). Empty path =
    // disabled (legacy unauthenticated submission path). Non-empty:
    // load registry, set up a per-tenant token-bucket limiter, and
    // gate every stdin submission through `verify_and_admit`.
    let auth_state: Option<Arc<Mutex<AuthState>>> = if tenants_path.is_empty() {
        None
    } else {
        let registry = TenantRegistry::load_from_path(&tenants_path)?;
        tracing::info!(
            "[coordinator] auth gate enabled ({} tenant(s) loaded from {})",
            registry.len(),
            tenants_path
        );
        // Default bucket params here are placeholders — every
        // `verify_and_admit` call passes per-tenant capacity +
        // refill via `accept_with_config`.
        let limiter = RateLimiter::new(SystemClock, 0, 0);
        Some(Arc::new(Mutex::new(AuthState { registry, limiter })))
    };

    // Stdin submission queue (issue #32). Only initialized when
    // `--submit-stdin` was given. The reader thread closes the
    // sender when stdin EOFs; the main loop's `recv` returns Err
    // and the coord drains.
    let submission_rx = if submit_stdin {
        let (tx, rx) = sync_channel::<JobSubmission>(queue_cap);
        spawn_stdin_reader(tx, auth_state.clone());
        tracing::info!(
            "[coordinator] --submit-stdin enabled (queue cap {queue_cap}); reading NDJSON job submissions from stdin"
        );
        Some(rx)
    } else {
        None
    };

    let mut completed: u64 = 0;

    'outer: while completed < max_jobs && !draining.load(Ordering::Relaxed) {
        let job_id = completed + 1;
        let (module, args) = if let Some(rx) = submission_rx.as_ref() {
            // Stdin-submitted jobs (issue #32). `recv_timeout` lets
            // the loop notice SIGTERM/SIGINT between submissions
            // instead of blocking forever on an idle stdin.
            let sub = loop {
                if draining.load(Ordering::Relaxed) {
                    break 'outer;
                }
                match rx.recv_timeout(Duration::from_millis(250)) {
                    Ok(sub) => break sub,
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        tracing::info!(
                            "[coordinator] stdin closed and queue drained — shutting down"
                        );
                        break 'outer;
                    }
                }
            };
            tracing::info!(
                "[coordinator] job {job_id} submitted: kind={:?} a={} b={} deadline_secs={}",
                sub.kind,
                sub.a,
                sub.b,
                sub.deadline_secs
            );
            let module = match sub.kind {
                JobKind::Add => &add_wasm,
                JobKind::Mul => &mul_wasm,
            };
            let args = encode_args(sub.a, sub.b).expect("encode args");
            (module, args)
        } else {
            // Legacy: round-robin canned add/mul with the
            // `--a` / `--b` flag pair.
            let module = if job_id % 2 == 1 {
                &add_wasm
            } else {
                &mul_wasm
            };
            let args = encode_args(job_a, job_b).expect("encode args");
            (module, args)
        };
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
            &mut stake_ledger,
            slash_fraction,
            runner_timeout_secs,
            &log,
            &records,
            journal.as_ref(),
        ) {
            Ok(()) => {
                completed += 1;
            }
            Err(e) => {
                tracing::warn!("[coordinator] job {job_id} aborted: {e}");
                completed += 1;
            }
        }
    }

    if draining.load(Ordering::Relaxed) {
        tracing::info!("[coordinator] draining (signal received), shutting down agents");
    } else {
        tracing::info!("[coordinator] reached max-jobs={max_jobs}, shutting down agents");
    }

    for a in agents.iter_mut() {
        let _ = write_envelope(&mut a.stream, &Envelope::Shutdown);
        let _ = a.stream.sock.shutdown(std::net::Shutdown::Both);
    }
    tracing::info!("[coordinator] done — completed {completed} job(s)");
    Ok(())
}

// ────────────────────────────────────────────────────────────────────────
// Job lifecycle
// ────────────────────────────────────────────────────────────────────────

fn accept_fleet(
    listener: &TcpListener,
    shared_cfg: &SharedServerConfig,
    fleet: u64,
    enrollment: Option<&EnrollmentSet>,
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
                tracing::warn!("[coordinator] ServerConnection::new for {peer}: {e}");
                continue;
            }
        };
        let mut stream = ServerStream::new(conn, tcp);

        let env = match read_envelope(&mut stream) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!("[coordinator] handshake/read failed for {peer}: {e}");
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
            tracing::warn!("[coordinator] dropping non-Register from {peer}");
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
            tracing::warn!(
                "[coordinator] dropping {peer}: registration VRF proof rejected ({e:?})"
            );
            continue;
        }

        // Enrollment gate (issue #45). After mTLS + VRF-of-possession,
        // the operator's enrollment list is the final say on whether
        // this runner is allowed in the trust set. Empty list = gate
        // disabled (legacy behavior).
        if let Some(set) = enrollment {
            let signing_fp = fingerprint(&signing_pubkey);
            let vrf_fp = fingerprint(&vrf_pubkey);
            if !set.is_enrolled(runner_id, &signing_fp, &vrf_fp) {
                tracing::warn!(
                    "[coordinator] rejecting unenrolled agent runner_id={} from {} (signing_fp={}, vrf_fp={})",
                    runner_id,
                    peer,
                    fingerprint_hex(&signing_fp),
                    fingerprint_hex(&vrf_fp)
                );
                continue;
            }
        }

        let signing_pk = match VerifyingKey::from_bytes(&signing_pubkey) {
            Ok(pk) => pk,
            Err(e) => {
                tracing::warn!("[coordinator] bad signing pubkey from {peer}: {e}");
                continue;
            }
        };
        if let Err(e) = write_envelope(&mut stream, &Envelope::RegisterAck) {
            tracing::warn!("[coordinator] ack write failed for {peer}: {e}");
            continue;
        }
        tracing::info!(
            "[coordinator] registered runner {} from {} (stake {}, mTLS ✓, VRF ✓, platform={:?}, runtimes={:?})",
            runner_id,
            peer,
            stake,
            capabilities.platform,
            capabilities.runtimes
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
    stake_ledger: &mut StakeLedger,
    slash_fraction: f32,
    runner_timeout_secs: u64,
    log: &Arc<Mutex<LogBackend>>,
    records: &Arc<Mutex<HashMap<u64, JobRecord>>>,
    journal: Option<&Arc<Mutex<Journal>>>,
) -> std::io::Result<()> {
    // Journal: JobSubmitted (issue #51). The internal demo loop
    // submits jobs in-process, but the lifecycle event is the same
    // shape as it'll be when #32 lands.
    journal_append(journal, &JournalEntry::JobSubmitted { job_id });

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
            tracing::warn!(
                "[coordinator] runner {} returned {:?}, expected VrfClaim",
                ag.runner_id,
                env
            );
            continue;
        };
        if claim_job_id != job_id {
            tracing::warn!(
                "[coordinator] runner {} VrfClaim job_id mismatch ({} != {})",
                ag.runner_id,
                claim_job_id,
                job_id
            );
            continue;
        }
        if let Err(e) = vrf_verify(&ag.vrf_pk, &job_seed, &vrf_output, &vrf_proof) {
            tracing::warn!(
                "[coordinator] runner {} VrfClaim proof rejected ({:?}); excluding from selection",
                ag.runner_id,
                e
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
        tracing::warn!(
            "[coordinator] job {job_id} ABORTED: only {eligible_count} of {} runner(s) match requirements ({:?} / {} cpu / {} MiB / runtimes {:?}); need {committee_size}",
            candidates.len(),
            requirements.platform,
            requirements.cpu,
            requirements.memory_mb,
            requirements.runtimes
        );
        return Ok(());
    };
    tracing::info!(
        "[coordinator] job {job_id} committee: {committee:?} module={:02x?}… ({} bytes), pipeline ({} step(s))",
        &mh[..4],
        log_module.len(),
        pipeline.steps.len()
    );

    // Journal: CommitteeSelected (issue #51).
    journal_append(
        journal,
        &JournalEntry::CommitteeSelected {
            job_id,
            committee: committee.clone(),
        },
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

    // ── Phase 2d: collect SubmitAttestation (issue #61: partial-tolerant) ──
    // Each runner gets a per-call read deadline. A runner that
    // doesn't respond within the deadline is recorded as missing
    // and the loop continues; the responding subset still aggregates
    // to a deterministic outcome, and the missing runners surface in
    // the log for downstream reputation tracking.
    let mut attestations = Vec::with_capacity(committee.len());
    let mut missing: Vec<RunnerId> = Vec::new();
    let runner_timeout = std::time::Duration::from_secs(runner_timeout_secs);
    for ag in agents.iter_mut() {
        if !committee.contains(&ag.runner_id) {
            continue;
        }
        let _ = ag.stream.sock.set_read_timeout(Some(runner_timeout));
        let read_result = read_envelope(&mut ag.stream);
        let _ = ag.stream.sock.set_read_timeout(None);
        let env = match read_result {
            Ok(e) => e,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                tracing::warn!(
                    "[coordinator] job {} runner {} attestation timeout after {}s — recorded as missing",
                    job_id,
                    ag.runner_id,
                    runner_timeout_secs
                );
                missing.push(ag.runner_id);
                continue;
            }
            Err(e) => {
                tracing::warn!(
                    "[coordinator] job {} runner {} attestation read failed ({e}) — recorded as missing",
                    job_id,
                    ag.runner_id
                );
                missing.push(ag.runner_id);
                continue;
            }
        };
        let Envelope::SubmitAttestation(att) = env else {
            tracing::warn!(
                "[coordinator] runner {} returned {:?}, expected SubmitAttestation",
                ag.runner_id,
                env
            );
            missing.push(ag.runner_id);
            continue;
        };
        let sig_ok = att.verify_signature(&ag.signing_pk);
        tracing::info!(
            "[coordinator] job {} runner {} attestation sig={} artifact={:02x?}…",
            job_id,
            ag.runner_id,
            if sig_ok { "ok" } else { "BAD" },
            &att.artifact_hash[..4]
        );
        if sig_ok {
            // Journal: AttestationReceived (issue #51). We only
            // record signature-valid attestations — a bad-sig
            // submission is treated like a missing one and surfaces
            // via the partial-tolerance counter, not the journal.
            journal_append(
                journal,
                &JournalEntry::AttestationReceived {
                    job_id,
                    runner_id: ag.runner_id,
                },
            );
            attestations.push(att);
        } else {
            // Bad-sig attestation is treated like a missing one for
            // the partial-tolerance ledger: the runner produced
            // unverifiable output and shouldn't contribute to
            // quorum. Slashing this case is out of scope for #61.
            missing.push(ag.runner_id);
        }
    }
    if !missing.is_empty() {
        tracing::info!(
            "[coordinator] job {} missing attestations: {:?} ({} of {} committee)",
            job_id,
            missing,
            missing.len(),
            committee.len()
        );
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
    let stake_snapshot = stake_ledger.as_stake_map();
    let committee_stake: Weight = committee
        .iter()
        .map(|id| stake_snapshot.get(id).copied().unwrap_or(0))
        .sum();
    let threshold = (committee_stake * 2).div_ceil(3);
    let outcome = aggregate(&votes, threshold, &stake_snapshot);
    let consensus_artifact = artifact_counts
        .iter()
        .max_by_key(|&(_, c)| *c)
        .map(|(k, _)| *k)
        .unwrap_or([0_u8; 32]);
    tracing::info!(
        "[coordinator] job {} outcome {:?} (threshold {}, committee stake {})",
        job_id,
        outcome,
        threshold,
        committee_stake
    );

    // Journal: Aggregated (issue #51). Records the outcome + the
    // consensus artifact hash so a recovering coord knows what to
    // re-anchor.
    journal_append(
        journal,
        &JournalEntry::Aggregated {
            job_id,
            outcome: outcome_to_journal(outcome),
            artifact_hex: hex_lower(&consensus_artifact),
        },
    );

    // Slashing (issue #35). On a definitive outcome (Pass or Fail),
    // any committee member whose attestation diverges from the
    // consensus artifact loses `current_stake × slash_fraction`
    // weight. The majority is untouched. Skipped on Escalate (no
    // consensus to compare against).
    if matches!(outcome, Outcome::Pass | Outcome::Fail) && slash_fraction > 0.0 {
        let events = stake_ledger.slash_minority(consensus_artifact, &attestations, slash_fraction);
        for event in &events {
            tracing::info!(
                "[coordinator] job {} slashed runner {} by {} ({} → {})",
                job_id,
                event.runner_id,
                event.slashed,
                event.stake_before,
                event.stake_after
            );
        }
    }

    if outcome == Outcome::Pass {
        // Compute pipeline_hash for the retrieval record. Canonical
        // CBOR encoding of the typed pipeline → SHA-256.
        let pipeline_bytes = cosaci_jobs::canonical_encoding(&pipeline)
            .map_err(|e| std::io::Error::other(format!("canonical encoding of pipeline: {e:?}")))?;
        let pipeline_hash = hash_bytes(&pipeline_bytes);

        // Append + record under the same lock so registry / log stay
        // mutually consistent for any concurrent retrieval.
        let (pos, length, root) = {
            let mut log_g = log.lock().expect("log mutex poisoned");
            let pos = log_g.append(consensus_artifact)?;
            let length = log_g.len();
            let root = log_g.root().expect("nonempty");
            (pos, length, root)
        };
        let record = JobRecord {
            job_id,
            pipeline_hash,
            committee_attestations: attestations.clone(),
            consensus_artifact,
            log_position: pos,
            log_length_at_anchor: length,
        };
        records
            .lock()
            .expect("records mutex poisoned")
            .insert(job_id, record);

        tracing::info!(
            "[coordinator] job {} anchored at position {} root {:02x?}…",
            job_id,
            pos,
            &root[..8]
        );

        // Journal: Anchored (issue #51). The terminal entry for a
        // successful job. A crash between Aggregated and Anchored
        // leaves the job in `pending_re_anchor`; on recovery, the
        // operator re-anchors via the read API or admin tooling.
        journal_append(
            journal,
            &JournalEntry::Anchored {
                job_id,
                position: pos,
            },
        );
    }
    Ok(())
}

/// Lowercase-hex encoding of a 32-byte hash. Used for journal
/// records where the operator + parser both want a human-readable
/// shape.
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{b:02x}").expect("write to String");
    }
    s
}

// ────────────────────────────────────────────────────────────────────────
// Stdin submission reader (issue #32) + auth gate (issue #46)
// ────────────────────────────────────────────────────────────────────────

/// Mutable state the stdin reader consults on every line: the
/// loaded tenant registry + a per-tenant token-bucket limiter.
/// Wrapped in `Arc<Mutex<...>>` because the reader thread mutates
/// the limiter (consuming tokens) on each accepted submission.
struct AuthState {
    registry: TenantRegistry,
    limiter: RateLimiter<SystemClock>,
}

/// Spawn a daemon thread that reads NDJSON `JobSubmission` records
/// from stdin and pushes them to the bounded queue. Each line is
/// parsed independently — a malformed line is logged and skipped,
/// so a single typo in a submission file doesn't abort the stream.
///
/// On a full queue, `try_send` returns `Full` and we log + drop the
/// record (reject-rather-than-block; documented backpressure
/// policy). When stdin EOFs, the thread drops the sender so the
/// main loop's `recv_timeout` returns `Disconnected` and the
/// coordinator drains.
///
/// When `auth_state` is `Some`, every parsed submission is gated
/// through `cosaci_state::submission_auth::verify_and_admit`
/// before it can enter the queue. Failed auth verdicts log a
/// reason at the warn level and the submission is dropped.
fn spawn_stdin_reader(tx: SyncSender<JobSubmission>, auth_state: Option<Arc<Mutex<AuthState>>>) {
    thread::spawn(move || {
        let stdin = std::io::stdin();
        let reader = stdin.lock();
        for (lineno, line) in reader.lines().enumerate() {
            let line = match line {
                Ok(l) => l,
                Err(e) => {
                    tracing::warn!("[coordinator] stdin read error at line {}: {e}", lineno + 1);
                    break;
                }
            };
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let sub: JobSubmission = match serde_json::from_str(trimmed) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(
                        "[coordinator] stdin line {} rejected: {e} (line: {trimmed})",
                        lineno + 1
                    );
                    continue;
                }
            };
            // Issue #46: auth gate. When `auth_state` is set,
            // `verify_and_admit` decides admission. Failed
            // submissions are dropped before the queue.
            if let Some(state) = auth_state.as_ref() {
                let mut g = state.lock().expect("auth state poisoned");
                let AuthState {
                    ref registry,
                    ref mut limiter,
                } = *g;
                let verdict = check_submission(&sub, registry, limiter);
                match verdict {
                    AuthCheck::Ok => {}
                    AuthCheck::UnknownTenant => {
                        tracing::warn!(
                            "[coordinator] auth gate: unknown tenant_id={:?} (kind={:?} a={} b={})",
                            sub.tenant_id,
                            sub.kind,
                            sub.a,
                            sub.b
                        );
                        continue;
                    }
                    AuthCheck::BadSignature => {
                        tracing::warn!(
                            "[coordinator] auth gate: bad signature (tenant_id={:?} kind={:?} a={} b={})",
                            sub.tenant_id,
                            sub.kind,
                            sub.a,
                            sub.b
                        );
                        continue;
                    }
                    AuthCheck::RateLimited => {
                        tracing::warn!(
                            "[coordinator] auth gate: rate-limited (tenant_id={:?} kind={:?} a={} b={})",
                            sub.tenant_id,
                            sub.kind,
                            sub.a,
                            sub.b
                        );
                        continue;
                    }
                }
            }
            match tx.try_send(sub) {
                Ok(()) => {}
                Err(TrySendError::Full(dropped)) => {
                    tracing::warn!(
                        "[coordinator] submission queue full, dropping record (kind={:?} a={} b={}); raise --queue-cap or slow producers",
                        dropped.kind,
                        dropped.a,
                        dropped.b
                    );
                }
                Err(TrySendError::Disconnected(_)) => {
                    tracing::warn!("[coordinator] submission receiver gone; stopping reader");
                    return;
                }
            }
        }
        tracing::info!("[coordinator] stdin EOF; submission reader exiting");
        // Dropping `tx` here closes the channel.
    });
}

/// Translate the wire-shape `JobSubmission` into a canonical
/// `JobSubmissionPayload`, then run `verify_and_admit` against
/// the tenant registry + rate limiter. Missing or malformed auth
/// fields are reported as `BadSignature` (the deliberately-merged
/// signature-failure verdict; see hypothesis card).
fn check_submission(
    sub: &JobSubmission,
    registry: &TenantRegistry,
    limiter: &mut RateLimiter<SystemClock>,
) -> AuthCheck {
    let (Some(tenant_id), Some(nonce), Some(pubkey_hex), Some(signature_hex)) = (
        sub.tenant_id,
        sub.nonce,
        sub.pubkey_hex.as_ref(),
        sub.signature_hex.as_ref(),
    ) else {
        return AuthCheck::BadSignature;
    };
    let Some(pubkey) = parse_hex32(pubkey_hex) else {
        return AuthCheck::BadSignature;
    };
    let Some(signature) = parse_hex64(signature_hex) else {
        return AuthCheck::BadSignature;
    };
    let payload = JobSubmissionPayload {
        tenant_id,
        kind: sub.kind.as_wire().to_string(),
        a: sub.a,
        b: sub.b,
        deadline_secs: sub.deadline_secs,
        nonce,
    };
    verify_and_admit(&payload, &pubkey, &signature, registry, limiter)
}

/// Parse 128 lowercase-hex chars into a `[u8; 64]` (an ed25519
/// signature). Returns `None` for any non-hex character or wrong
/// length.
fn parse_hex64(s: &str) -> Option<[u8; 64]> {
    if s.len() != 128 {
        return None;
    }
    let mut out = [0_u8; 64];
    for (i, byte_pair) in s.as_bytes().chunks_exact(2).enumerate() {
        let hi = hex_nibble(byte_pair[0])?;
        let lo = hex_nibble(byte_pair[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
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
                    tracing::warn!(
                        "[coordinator] SIGHUP: server config reloaded (cert={cert_path}, crl={})",
                        if crl_path.is_empty() {
                            "<none>"
                        } else {
                            crl_path.as_str()
                        }
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        "[coordinator] SIGHUP: reload failed ({e}); keeping previous config"
                    );
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

/// Append a journal entry under the `Arc<Mutex<Journal>>`. A None
/// journal is a no-op (operator opted out of journaling). Errors
/// are logged but don't fail the job — the journal is best-effort
/// observability; the source of truth for "did this job complete"
/// is the Merkle log.
fn journal_append(journal: Option<&Arc<Mutex<Journal>>>, entry: &JournalEntry) {
    let Some(j) = journal else {
        return;
    };
    let mut guard = match j.lock() {
        Ok(g) => g,
        Err(e) => {
            tracing::warn!("[coordinator] journal mutex poisoned: {e}");
            return;
        }
    };
    if let Err(e) = guard.append(entry) {
        tracing::warn!("[coordinator] journal append failed ({e}) — continuing");
    }
}

/// Map `cosaci_core::quorum::Outcome` to the journal's `JournalOutcome`.
fn outcome_to_journal(o: Outcome) -> JournalOutcome {
    match o {
        Outcome::Pass => JournalOutcome::Pass,
        Outcome::Fail => JournalOutcome::Fail,
        Outcome::Retry => JournalOutcome::Retry,
        Outcome::Escalate => JournalOutcome::Escalate,
    }
}

/// Initialize structured tracing (issue #47, partial).
///
/// `tracing-subscriber::fmt` writes pretty-printed lines to stderr.
/// `RUST_LOG` controls per-target verbosity (`RUST_LOG=coordinator=debug`).
/// Default level is `info`; the subscriber is permissive about
/// duplicate-init (the `try_init` swallows the error so a child process
/// or an embedded test harness can re-init without panicking).
///
/// Out of scope here: Prometheus metrics endpoint, OTLP traces. Both
/// land alongside the coord-side observability HTTP path that #47
/// follow-on work will wire in.
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

    fn len(&self) -> u64 {
        match self {
            Self::Mem(l) => l.len(),
            Self::File(l) => l.len(),
        }
    }

    fn build_bundle(
        &self,
        records: &HashMap<u64, JobRecord>,
        job_id: u64,
    ) -> Option<cosaci_core::retrieval::JobBundle> {
        match self {
            Self::Mem(l) => build_bundle(records, l, job_id),
            Self::File(l) => build_bundle(records, l, job_id),
        }
    }
}

// ────────────────────────────────────────────────────────────────────────
// Read API server (issue #44)
// ────────────────────────────────────────────────────────────────────────

/// Spawn the read-side TLS listener. Daemon thread; dies on process
/// exit. Each accepted connection is handled on its own short-lived
/// thread — read clients send one request envelope and read one
/// response envelope, then disconnect.
fn spawn_read_server(
    addr: String,
    shared_cfg: SharedServerConfig,
    records: Arc<Mutex<HashMap<u64, JobRecord>>>,
    log: Arc<Mutex<LogBackend>>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(&addr)?;
    thread::spawn(move || {
        loop {
            let (tcp, peer) = match listener.accept() {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!("[coordinator/read] accept error: {e}");
                    continue;
                }
            };
            let _ = tcp.set_nodelay(true);
            let cfg_snapshot = shared_cfg.lock().expect("shared cfg poisoned").clone();
            let conn = match ServerConnection::new(cfg_snapshot) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("[coordinator/read] ServerConnection::new for {peer}: {e}");
                    continue;
                }
            };
            let stream = ServerStream::new(conn, tcp);
            let records = records.clone();
            let log = log.clone();
            thread::spawn(move || handle_read_client(stream, peer, records, log));
        }
    });
    Ok(())
}

fn handle_read_client(
    mut stream: ServerStream,
    peer: std::net::SocketAddr,
    records: Arc<Mutex<HashMap<u64, JobRecord>>>,
    log: Arc<Mutex<LogBackend>>,
) {
    let req = match read_envelope(&mut stream) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!("[coordinator/read] {peer}: read failed: {e}");
            return;
        }
    };
    let resp = match req {
        Envelope::GetJob { job_id } => {
            let recs = records.lock().expect("records mutex poisoned");
            let log_g = log.lock().expect("log mutex poisoned");
            match log_g.build_bundle(&recs, job_id) {
                Some(b) => Envelope::JobBundleResponse(b),
                None => Envelope::JobNotFound { job_id },
            }
        }
        Envelope::GetLogRoot => {
            let log_g = log.lock().expect("log mutex poisoned");
            Envelope::LogRoot {
                root: log_g.root(),
                length: log_g.len(),
            }
        }
        other => {
            tracing::warn!("[coordinator/read] {peer}: dropping non-read envelope {other:?}");
            return;
        }
    };
    if let Err(e) = write_envelope(&mut stream, &resp) {
        tracing::warn!("[coordinator/read] {peer}: write failed: {e}");
    }
}
