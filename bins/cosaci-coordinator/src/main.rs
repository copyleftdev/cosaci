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
use cosaci_core::merkle_log::{FileStore, MerkleLog, hash_bytes};
use cosaci_core::quorum::{Outcome, RunnerId, Vote, VoteResult, Weight, aggregate};
use cosaci_core::retrieval::{JobRecord, build_bundle};
use cosaci_core::signing::VerifyingKey;
use cosaci_protocol::proto::{Envelope, VRF_REGISTRATION_CHALLENGE, read_envelope, write_envelope};
use cosaci_protocol::tls::{install_crypto_provider, server_config_from_paths_with_crl};
use cosaci_state::enrollment::{EnrollmentSet, fingerprint, fingerprint_hex};
use cosaci_state::journal::{Journal, JournalEntry, JournalOutcome, reconstruct_state, replay};
use cosaci_state::stake_ledger::StakeLedger;
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

    let enrollment: Option<Arc<EnrollmentSet>> = if enrollment_path.is_empty() {
        None
    } else {
        let set = EnrollmentSet::load_from_path(&enrollment_path)?;
        println!(
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
        println!(
            "[coordinator] journal replayed from {}: {} entries, {} previously-anchored job(s), {} pending re-run, {} pending re-anchor",
            journal_path,
            entries.len(),
            anchored_count,
            pending_run.len(),
            pending_anchor.len()
        );
        if !pending_run.is_empty() {
            println!(
                "[coordinator] journal pending re-run job_ids: {:?} (NOT auto-rerun in v0.3 — see #32 + #51 follow-on)",
                pending_run
            );
        }
        if !pending_anchor.is_empty() {
            println!(
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

    println!("[coordinator] listening on {addr} (mTLS)");
    let listener = TcpListener::bind(&addr)?;

    // ── Phase 1: accept fleet + verify registration VRF proofs ─────────────
    let mut agents = accept_fleet(&listener, &shared_cfg, fleet, enrollment.as_deref())?;
    // Stake ledger (issue #35): seeded from registration-time stakes,
    // mutated as the job loop slashes minority disagreers. The
    // quorum threshold is computed against the current ledger state,
    // so a slashed runner's voting weight shrinks immediately.
    let mut stake_ledger =
        StakeLedger::from_stake_map(agents.iter().map(|a| (a.runner_id, a.stake)).collect());
    println!(
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
        println!(
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
        println!("[coordinator] read API listening on {read_addr} (mTLS)");
    }

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

        // Enrollment gate (issue #45). After mTLS + VRF-of-possession,
        // the operator's enrollment list is the final say on whether
        // this runner is allowed in the trust set. Empty list = gate
        // disabled (legacy behavior).
        if let Some(set) = enrollment {
            let signing_fp = fingerprint(&signing_pubkey);
            let vrf_fp = fingerprint(&vrf_pubkey);
            if !set.is_enrolled(runner_id, &signing_fp, &vrf_fp) {
                eprintln!(
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
                eprintln!(
                    "[coordinator] job {} runner {} attestation timeout after {}s — recorded as missing",
                    job_id, ag.runner_id, runner_timeout_secs
                );
                missing.push(ag.runner_id);
                continue;
            }
            Err(e) => {
                eprintln!(
                    "[coordinator] job {} runner {} attestation read failed ({e}) — recorded as missing",
                    job_id, ag.runner_id
                );
                missing.push(ag.runner_id);
                continue;
            }
        };
        let Envelope::SubmitAttestation(att) = env else {
            eprintln!(
                "[coordinator] runner {} returned {:?}, expected SubmitAttestation",
                ag.runner_id, env
            );
            missing.push(ag.runner_id);
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
        println!(
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
    println!(
        "[coordinator] job {} outcome {:?} (threshold {}, committee stake {})",
        job_id, outcome, threshold, committee_stake
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
            println!(
                "[coordinator] job {} slashed runner {} by {} ({} → {})",
                job_id, event.runner_id, event.slashed, event.stake_before, event.stake_after
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

        println!(
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
            eprintln!("[coordinator] journal mutex poisoned: {e}");
            return;
        }
    };
    if let Err(e) = guard.append(entry) {
        eprintln!("[coordinator] journal append failed ({e}) — continuing");
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
                    eprintln!("[coordinator/read] accept error: {e}");
                    continue;
                }
            };
            let _ = tcp.set_nodelay(true);
            let cfg_snapshot = shared_cfg.lock().expect("shared cfg poisoned").clone();
            let conn = match ServerConnection::new(cfg_snapshot) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("[coordinator/read] ServerConnection::new for {peer}: {e}");
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
            eprintln!("[coordinator/read] {peer}: read failed: {e}");
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
            eprintln!("[coordinator/read] {peer}: dropping non-read envelope {other:?}");
            return;
        }
    };
    if let Err(e) = write_envelope(&mut stream, &resp) {
        eprintln!("[coordinator/read] {peer}: write failed: {e}");
    }
}
