//! End-to-end CosaCI demo — single-process wire-up of every primitive.
//!
//! Submits one job, VRF-assigns runners from a registered fleet, has
//! each runner execute the canned WASM, signs + verifies attestations,
//! aggregates via stake-weighted quorum, and anchors the result into
//! the Merkle log.
//!
//! Run with `cargo run --bin demo`. No network, no state on disk — the
//! whole job lifecycle runs in-process.

use std::collections::HashMap;

use cosaci::attestation::{Attestation, AttestationResult};
use cosaci::clock::{Clock, SystemClock};
use cosaci::lease::LeaseManager;
use cosaci::merkle_log::MerkleLog;
use cosaci::quorum::{Outcome, RunnerId, StakeMap, Vote, VoteResult, Weight, aggregate};
use cosaci::registry::{Registry, RunnerInfo};
use cosaci::signing::{Keypair, VerifyingKey};
use cosaci::vrf::VrfKeypair;
use cosaci::wasm_runtime::{execute_add, output_hash};

/// One runner's in-process state.
struct Agent {
    id: RunnerId,
    signing: Keypair,
    signing_pk: VerifyingKey,
    vrf: VrfKeypair,
    vrf_pk_bytes: [u8; 32],
    stake: u64,
}

impl Agent {
    fn new(id: RunnerId, stake: u64) -> Self {
        // Deterministic per-id seeds so the demo is reproducible.
        let mut signing_seed = [0_u8; 32];
        let mut vrf_seed = [0_u8; 32];
        signing_seed[..8].copy_from_slice(&id.to_le_bytes());
        vrf_seed[..8].copy_from_slice(&id.to_le_bytes());
        vrf_seed[8] = 0xff; // differentiate from signing seed
        let signing = Keypair::from_seed(signing_seed);
        let signing_pk = signing.verifying_key();
        let vrf = VrfKeypair::from_seed(vrf_seed);
        let vrf_pk_bytes = vrf.public_key_bytes();
        Self {
            id,
            signing,
            signing_pk,
            vrf,
            vrf_pk_bytes,
            stake,
        }
    }
}

/// The coordinator's view of the cluster.
struct Coordinator {
    registry: Registry,
    stake: StakeMap,
    // Per-runner pubkeys for VRF and signature verification.
    vrf_pks: HashMap<RunnerId, [u8; 32]>,
    signing_pks: HashMap<RunnerId, VerifyingKey>,
    lease_mgr: LeaseManager<SystemClock>,
    log: MerkleLog,
}

const COMMIT_SHA: [u8; 32] = [0x42; 32];
const LEASE_TTL_NS: u64 = 60_000_000_000; // 60s

fn main() {
    println!("═══════════════════════════════════════════════════════════════");
    println!(" CosaCI demo — single-process end-to-end job lifecycle");
    println!("═══════════════════════════════════════════════════════════════\n");

    // ─── 1. Spin up fleet ────────────────────────────────────────────────
    let fleet_size: u64 = 5;
    let stake_per: u64 = 100;
    let agents: Vec<Agent> = (0..fleet_size)
        .map(|i| Agent::new(i as RunnerId, stake_per))
        .collect();
    println!(
        "▸ Fleet: {} runners, stake {} each (total {})",
        fleet_size,
        stake_per,
        fleet_size * stake_per
    );

    // ─── 2. Coordinator registers them ───────────────────────────────────
    let clock = SystemClock;
    let mut coord = Coordinator {
        registry: Registry::new(),
        stake: HashMap::new(),
        vrf_pks: HashMap::new(),
        signing_pks: HashMap::new(),
        lease_mgr: LeaseManager::new(clock, LEASE_TTL_NS),
        log: MerkleLog::new(),
    };
    for agent in &agents {
        coord.registry.register(
            agent.id,
            RunnerInfo {
                pubkey: agent.signing_pk.to_bytes(),
                stake: agent.stake,
            },
        );
        coord.stake.insert(agent.id, agent.stake);
        coord.vrf_pks.insert(agent.id, agent.vrf_pk_bytes);
        coord.signing_pks.insert(agent.id, agent.signing_pk);
    }
    println!("▸ Registry: {} registered\n", coord.registry.len());

    // ─── 3. Submit a job ─────────────────────────────────────────────────
    let job_id: u64 = 1;
    let job_input: (i32, i32) = (21, 21);
    let job_seed = job_seed_bytes(job_id);
    println!(
        "▸ Job {}: WASM add({}, {}) → expected {}",
        job_id,
        job_input.0,
        job_input.1,
        job_input.0.wrapping_add(job_input.1)
    );

    // ─── 4. VRF-assign K runners (lowest VRF output wins a slot) ─────────
    let committee_size: usize = 3;
    let assigned = vrf_assign_committee(&agents, &job_seed, committee_size);
    println!("▸ VRF committee: runners {:?}", assigned);

    // ─── 5. Coordinator issues leases ────────────────────────────────────
    // NOTE: the current LeaseManager enforces `one active lease per job_id`,
    // but a quorum-based CI needs K leases per job (one per committee member).
    // For this v0.1 demo we use the job_id as the lease key for the first
    // runner only; v0.2 will likely want a `(job_id, runner_id)` composite
    // key or a committee-lease primitive. The failed-lease log lines below
    // are the architectural signal, not a runtime bug.
    for &runner_id in &assigned {
        match coord.lease_mgr.acquire(job_id, runner_id) {
            Ok(lease_id) => println!("  · lease {} issued to runner {}", lease_id, runner_id),
            Err(_) => println!(
                "  · lease rejected for runner {} (single-lease-per-job; see note)",
                runner_id
            ),
        }
    }

    // ─── 6. Assigned runners execute WASM and sign attestations ──────────
    let mut attestations: Vec<Attestation> = Vec::new();
    for &runner_id in &assigned {
        let agent = &agents[runner_id as usize];
        let result = execute_add(job_input.0, job_input.1).expect("wasm execution");
        let artifact = output_hash(result);
        let mut att = Attestation {
            version: Attestation::VERSION,
            job_id: u64_to_uuid(job_id),
            commit: COMMIT_SHA,
            runner_id,
            result: AttestationResult::Pass,
            environment_hash: [0xee; 32],
            artifact_hash: artifact,
            timestamp_unix_ns: coord.lease_mgr_clock_now(),
            signature: [0_u8; 64],
        };
        att.sign_with(&agent.signing);
        attestations.push(att);
    }
    println!(
        "▸ {} attestations signed (one per committee member)",
        attestations.len()
    );

    // ─── 7. Coordinator verifies signatures + consistency ────────────────
    let mut verified_votes: Vec<Vote> = Vec::new();
    let mut seen_artifacts: HashMap<[u8; 32], u32> = HashMap::new();
    for att in &attestations {
        let pk = coord
            .signing_pks
            .get(&att.runner_id)
            .expect("registered runner");
        let sig_ok = att.verify_signature(pk);
        let count = seen_artifacts.entry(att.artifact_hash).or_insert(0);
        *count += 1;
        if sig_ok {
            verified_votes.push(Vote {
                runner_id: att.runner_id,
                result: match att.result {
                    AttestationResult::Pass => VoteResult::Pass,
                    AttestationResult::Fail => VoteResult::Fail,
                },
            });
        }
        println!(
            "  · runner {} sig={} artifact={:x?}…",
            att.runner_id,
            if sig_ok { "ok" } else { "BAD" },
            &att.artifact_hash[..4]
        );
    }
    let consensus_artifact = seen_artifacts
        .iter()
        .max_by_key(|&(_, c)| *c)
        .map(|(k, _)| *k)
        .expect("at least one attestation");
    println!(
        "▸ Consensus artifact: {:x?}… ({} / {} agree)",
        &consensus_artifact[..8],
        seen_artifacts[&consensus_artifact],
        attestations.len()
    );

    // ─── 8. Quorum aggregate ─────────────────────────────────────────────
    // Threshold = ceil(2/3 of committee stake).
    let committee_stake: Weight = assigned
        .iter()
        .map(|id| coord.stake.get(id).copied().unwrap_or(0))
        .sum();
    let threshold = (committee_stake * 2 + 2) / 3; // ceil(2*stake/3)
    let outcome = aggregate(&verified_votes, threshold, &coord.stake);
    println!(
        "▸ Quorum: threshold {} (committee stake {}), outcome {:?}",
        threshold, committee_stake, outcome
    );

    // ─── 9. Anchor result into the Merkle log ────────────────────────────
    if outcome == Outcome::Pass {
        let position = coord.log.append(consensus_artifact);
        let root = coord.log.root().expect("nonempty after append");
        let peaks = coord.log.peak_hashes(coord.log.len());
        println!(
            "▸ Merkle log: position {}, root {:x?}…, {} peak(s)",
            position,
            &root[..8],
            peaks.len()
        );

        // Verify the inclusion proof of our freshly-appended entry.
        let proof = coord.log.inclusion_proof(position).expect("member");
        let verified = cosaci::merkle_log::verify_inclusion(&proof, root);
        println!(
            "▸ Inclusion proof verification: {}",
            if verified { "ok" } else { "BAD" }
        );
    }

    println!("\n═══════════════════════════════════════════════════════════════");
    println!(" Demo complete.");
    println!("═══════════════════════════════════════════════════════════════");
}

// ────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────

fn job_seed_bytes(job_id: u64) -> [u8; 32] {
    let mut seed = [0_u8; 32];
    seed[..8].copy_from_slice(&job_id.to_le_bytes());
    // Mix a small constant so seed != zero for job_id=0.
    seed[31] = 0xab;
    seed
}

fn u64_to_uuid(id: u64) -> [u8; 16] {
    let mut out = [0_u8; 16];
    out[..8].copy_from_slice(&id.to_le_bytes());
    out
}

fn vrf_assign_committee(agents: &[Agent], seed: &[u8; 32], k: usize) -> Vec<RunnerId> {
    let mut scored: Vec<(RunnerId, [u8; 32])> = agents
        .iter()
        .map(|a| (a.id, a.vrf.evaluate(seed).0))
        .collect();
    scored.sort_by(|a, b| a.1.cmp(&b.1));
    scored.into_iter().take(k).map(|(id, _)| id).collect()
}

impl Coordinator {
    fn lease_mgr_clock_now(&mut self) -> i64 {
        // Re-read through the lease manager's clock so timestamps agree
        // with lease expiry math. Using the lease manager's accessor
        // would need &mut; read through its clock by having one locally.
        SystemClock.now_ns() as i64
    }
}
