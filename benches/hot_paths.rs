//! Micro-benchmarks for CosaCI's hot paths.
//!
//! Closes `hypotheses/latency-sla.md` (Tier 4D) at the shape level:
//! concrete SLA thresholds are a product commitment (p99 < 90s for a
//! 1-minute test job, etc.), but the *per-operation* costs on the
//! critical path are measurable here and serve as a regression gate.
//!
//! Run with `cargo bench --bench hot_paths`. Baseline numbers live in
//! the card's `baseline_ns:` frontmatter.

// `c.bench_function("name", |b| b.iter(...))` is the standard
// criterion pattern; the closure's tail expression is a unit-returning
// `b.iter(...)` call. Pedantic flags every one of these as
// "missing trailing `;`" — there's nothing to gain by sprinkling
// semicolons through every benchmark.
#![allow(clippy::semicolon_if_nothing_returned)]

use std::collections::HashMap;

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};

use cosaci::attestation::{Attestation, AttestationResult, canonicalize, hash as att_hash};
use cosaci::gossip::{NodeState, merge};
use cosaci::quorum::{RunnerId, StakeMap, Vote, VoteResult, Weight, aggregate};
use cosaci::signing::{Keypair, verify as ed_verify};
use cosaci::verifier::{LeafHash, compute_root, inclusion_proof, verify_inclusion};
use cosaci::vrf::{VrfKeypair, verify as vrf_verify};

fn bench_quorum_aggregate(c: &mut Criterion) {
    // Five-runner stake-weighted quorum — the workhorse shape.
    let mut stake: StakeMap = HashMap::new();
    for i in 0_u64..5 {
        stake.insert(i as RunnerId, 100);
    }
    let votes: Vec<Vote> = (0_u64..5)
        .map(|i| Vote {
            runner_id: i as RunnerId,
            result: if i < 4 {
                VoteResult::Pass
            } else {
                VoteResult::Fail
            },
        })
        .collect();
    let threshold: Weight = 300;
    c.bench_function("quorum/aggregate-5x1", |b| {
        b.iter(|| aggregate(black_box(&votes), black_box(threshold), black_box(&stake)))
    });
}

fn sample_attestation() -> Attestation {
    Attestation {
        version: Attestation::VERSION,
        job_id: [7; 16],
        commit: [42; 32],
        runner_id: 17,
        result: AttestationResult::Pass,
        environment_hash: [0xaa; 32],
        artifact_hash: [0xbb; 32],
        timestamp_unix_ns: 1_700_000_000_000_000_000,
        signature: [0xcc; 64],
    }
}

fn bench_attestation_canonicalize(c: &mut Criterion) {
    let a = sample_attestation();
    c.bench_function("attestation/canonicalize", |b| {
        b.iter(|| canonicalize(black_box(&a)))
    });
    c.bench_function("attestation/hash", |b| b.iter(|| att_hash(black_box(&a))));
}

fn bench_ed25519(c: &mut Criterion) {
    let kp = Keypair::from_seed([1_u8; 32]);
    let pk = kp.verifying_key();
    let msg = b"cosaci attestation message, realistic length ~= 256 bytes ...";

    c.bench_function("ed25519/sign", |b| b.iter(|| kp.sign(black_box(msg))));
    let sig = kp.sign(msg);
    c.bench_function("ed25519/verify", |b| {
        b.iter(|| ed_verify(black_box(&pk), black_box(msg), black_box(&sig)))
    });
}

fn bench_vrf(c: &mut Criterion) {
    let kp = VrfKeypair::from_seed([2_u8; 32]);
    let pk = kp.public_key_bytes();
    let input = b"vrf-input-sample";

    c.bench_function("vrf/evaluate", |b| b.iter(|| kp.evaluate(black_box(input))));
    let (output, proof) = kp.evaluate(input);
    c.bench_function("vrf/verify", |b| {
        b.iter(|| {
            vrf_verify(
                black_box(&pk),
                black_box(input),
                black_box(&output),
                black_box(&proof),
            )
        })
    });
}

fn bench_merkle_verifier(c: &mut Criterion) {
    let leaves: Vec<LeafHash> = (0..16).map(|i| [i as u8; 32]).collect();

    c.bench_function("verifier/compute_root-16", |b| {
        b.iter(|| compute_root(black_box(&leaves)))
    });
    let root = compute_root(&leaves).expect("16 leaves");
    let proof = inclusion_proof(&leaves, leaves[7]).expect("member");
    c.bench_function("verifier/verify_inclusion-16", |b| {
        b.iter(|| verify_inclusion(black_box(&proof), black_box(root)))
    });
}

fn bench_gossip_merge(c: &mut Criterion) {
    let mut a = NodeState::new();
    let mut b = NodeState::new();
    for i in 0_u64..32 {
        a.write(i, i, i);
        b.write(i + 16, i + 16, i + 16);
    }
    c.bench_function("gossip/merge-32x32", |bench| {
        bench.iter(|| merge(black_box(&a), black_box(&b)))
    });
}

criterion_group!(
    hot_paths,
    bench_quorum_aggregate,
    bench_attestation_canonicalize,
    bench_ed25519,
    bench_vrf,
    bench_merkle_verifier,
    bench_gossip_merge
);
criterion_main!(hot_paths);
