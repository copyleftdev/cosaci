//! CosaCI coordinator — accepts agent registrations over TCP, runs one
//! job through VRF assignment + quorum aggregation + Merkle anchoring,
//! then shuts down. v0.1 is plaintext TCP; mTLS over `rustls::Stream`
//! is a drop-in at the `TcpStream` layer (`src/tls.rs` is the
//! handshake harness).
//!
//! Run with `cargo run --bin coordinator -- --addr 127.0.0.1:7878
//!                                           --committee 3`.

use std::collections::HashMap;
use std::env;
use std::net::{TcpListener, TcpStream};
use std::time::{SystemTime, UNIX_EPOCH};

use cosaci::attestation::AttestationResult;
use cosaci::merkle_log::MerkleLog;
use cosaci::proto::{read_envelope, write_envelope, Envelope};
use cosaci::quorum::{aggregate, Outcome, RunnerId, StakeMap, Vote, VoteResult, Weight};
use cosaci::signing::VerifyingKey;

struct RegisteredAgent {
    runner_id: RunnerId,
    stream: TcpStream,
    signing_pk: VerifyingKey,
    vrf_pk: [u8; 32],
    stake: u64,
}

fn main() -> std::io::Result<()> {
    // CLI: addr + committee size + fleet size
    let args: Vec<String> = env::args().collect();
    let addr = arg_or(&args, "--addr", "127.0.0.1:7878");
    let fleet: u64 = arg_or(&args, "--fleet", "5").parse().expect("fleet u64");
    let committee: usize = arg_or(&args, "--committee", "3")
        .parse()
        .expect("committee usize");
    let job_a: i32 = arg_or(&args, "--a", "21").parse().expect("a i32");
    let job_b: i32 = arg_or(&args, "--b", "21").parse().expect("b i32");

    println!("[coordinator] listening on {addr}");
    let listener = TcpListener::bind(&addr)?;

    // ── Accept `fleet` Register envelopes ───────────────────────────────
    let mut agents: Vec<RegisteredAgent> = Vec::with_capacity(fleet as usize);
    for _ in 0..fleet {
        let (mut stream, peer) = listener.accept()?;
        let env = read_envelope(&mut stream)?;
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
        write_envelope(&mut stream, &Envelope::RegisterAck)?;
        println!(
            "[coordinator] registered runner {} from {} (stake {})",
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
    println!("[coordinator] fleet assembled ({} agents)", agents.len());

    // ── Build the stake map + VRF-assign a committee ────────────────────
    let mut stake_map: StakeMap = HashMap::new();
    for a in &agents {
        stake_map.insert(a.runner_id, a.stake);
    }

    let job_id: u64 = 1;
    let job_seed = job_seed_bytes(job_id);
    // Committee selection: on the coordinator side we re-derive each
    // agent's VRF output using the agent-reported VRF public key,
    // via the VRFPreOut comparison pattern — but our schnorrkel wrapper
    // only signs on the private side. For v0.1 the coordinator uses
    // the agents' pubkeys as a stable ordering seed (lexmin(SHA256(vrf_pk || seed))).
    // A production coordinator would instead receive VRFProof from each
    // agent and verify, OR use a separately-broadcast committee rule.
    let committee = select_committee_by_pubkey_hash(&agents, &job_seed, committee);
    println!("[coordinator] committee: {committee:?}");

    // ── Broadcast Assign to committee ───────────────────────────────────
    let deadline = now_unix_ns() + 60_000_000_000; // +60s
    for a in agents.iter_mut() {
        if committee.contains(&a.runner_id) {
            write_envelope(
                &mut a.stream,
                &Envelope::Assign {
                    job_id,
                    a: job_a,
                    b: job_b,
                    deadline_unix_ns: deadline,
                },
            )?;
        }
    }

    // ── Collect SubmitAttestation from committee ────────────────────────
    let mut attestations = Vec::with_capacity(committee.len());
    for a in agents.iter_mut() {
        if !committee.contains(&a.runner_id) {
            continue;
        }
        let env = read_envelope(&mut a.stream)?;
        let Envelope::SubmitAttestation(att) = env else {
            eprintln!(
                "[coordinator] runner {} returned {:?}, expected SubmitAttestation",
                a.runner_id, env
            );
            continue;
        };
        let sig_ok = att.verify_signature(&a.signing_pk);
        println!(
            "[coordinator] runner {} attestation sig={} artifact={:02x?}…",
            a.runner_id,
            if sig_ok { "ok" } else { "BAD" },
            &att.artifact_hash[..4]
        );
        if sig_ok {
            attestations.push(att);
        }
    }

    // ── Aggregate via stake-weighted quorum ─────────────────────────────
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
    let threshold = (committee_stake * 2 + 2) / 3;
    let outcome = aggregate(&votes, threshold, &stake_map);
    let consensus_artifact = artifact_counts
        .iter()
        .max_by_key(|&(_, c)| *c)
        .map(|(k, _)| *k)
        .unwrap_or([0_u8; 32]);
    println!(
        "[coordinator] quorum outcome {:?} (threshold {}, committee stake {})",
        outcome, threshold, committee_stake
    );

    // ── Anchor into Merkle log if Pass ──────────────────────────────────
    if outcome == Outcome::Pass {
        let mut log = MerkleLog::new();
        let pos = log.append(consensus_artifact);
        let root = log.root().expect("nonempty");
        println!(
            "[coordinator] anchored at position {} root {:02x?}…",
            pos,
            &root[..8]
        );
    }

    // ── Tell agents to shut down ────────────────────────────────────────
    for a in agents.iter_mut() {
        let _ = write_envelope(&mut a.stream, &Envelope::Shutdown);
        let _ = a.stream.shutdown(std::net::Shutdown::Both);
    }
    println!("[coordinator] done");
    Ok(())
}

// ────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────

fn arg_or(args: &[String], flag: &str, default: &str) -> String {
    if let Some(pos) = args.iter().position(|a| a == flag) {
        if let Some(v) = args.get(pos + 1) {
            return v.clone();
        }
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

/// Committee selection for v0.1: sort agents by `SHA256(vrf_pk || seed)`,
/// pick the k with the smallest hash. Deterministic, verifiable by anyone
/// who knows the agents' VRF public keys — but not the VRF proof path
/// (which would require each agent to broadcast its VRFProof). A
/// production coordinator would use full VRF.
fn select_committee_by_pubkey_hash(
    agents: &[RegisteredAgent],
    seed: &[u8; 32],
    k: usize,
) -> Vec<RunnerId> {
    use sha2::{Digest, Sha256};
    let mut scored: Vec<(RunnerId, [u8; 32])> = agents
        .iter()
        .map(|a| {
            let mut h = Sha256::new();
            h.update(&a.vrf_pk);
            h.update(seed);
            let digest: [u8; 32] = h.finalize().into();
            (a.runner_id, digest)
        })
        .collect();
    scored.sort_by(|a, b| a.1.cmp(&b.1));
    scored.into_iter().take(k).map(|(id, _)| id).collect()
}
