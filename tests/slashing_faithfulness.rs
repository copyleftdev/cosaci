//! Property tests for `cosaci-state::stake_ledger::StakeLedger`.
//!
//! Encodes the falsifiable claims of `hypotheses/slashing-faithfulness.md`
//! (issue #35, class A).

use cosaci::attestation::{Attestation, AttestationResult};
use cosaci::quorum::Weight;
use cosaci::stake_ledger::{SlashEvent, StakeLedger};
use hegel::{TestCase, generators};

// ────────────────────────────────────────────────────────────────────────
// Hegel generators
// ────────────────────────────────────────────────────────────────────────

fn draw_hash(tc: &TestCase) -> [u8; 32] {
    let v: Vec<u8> = tc.draw(generators::binary().min_size(32).max_size(32));
    let mut h = [0_u8; 32];
    h.copy_from_slice(&v);
    h
}

fn make_attestation(runner_id: u64, artifact_hash: [u8; 32]) -> Attestation {
    Attestation {
        version: Attestation::VERSION,
        job_id: [0_u8; 16],
        commit: [0_u8; 32],
        runner_id,
        result: AttestationResult::Pass,
        environment_hash: [0_u8; 32],
        artifact_hash,
        timestamp_unix_ns: 0,
        signature: [0_u8; 64],
    }
}

/// Draw a small committee with stakes in [10, 1000]. Returns the
/// initial ledger state.
fn draw_ledger(tc: &TestCase) -> StakeLedger {
    let n = tc.draw(generators::integers::<usize>().min_value(2).max_value(8));
    let mut ledger = StakeLedger::new();
    for i in 0..n {
        let stake: Weight = tc.draw(
            generators::integers::<Weight>()
                .min_value(10)
                .max_value(1000),
        );
        ledger.register(i as u64, stake);
    }
    ledger
}

// ────────────────────────────────────────────────────────────────────────
// Property 1 — disagreers are slashed.
// ────────────────────────────────────────────────────────────────────────
#[hegel::test]
fn disagreement_runners_slashed(tc: TestCase) {
    let mut ledger = draw_ledger(&tc);
    let n = ledger.len() as u64;
    let consensus = draw_hash(&tc);
    let mut wrong = consensus;
    wrong[0] ^= 0x01;

    // Half the committee (rounding down) disagrees.
    let attestations: Vec<Attestation> = (0..n)
        .map(|i| {
            let h = if i % 2 == 0 { consensus } else { wrong };
            make_attestation(i, h)
        })
        .collect();
    let fraction: f32 = 0.25;
    let events = ledger.slash_minority(consensus, &attestations, fraction);

    // Every disagreer (odd-indexed runner) must appear in events.
    for i in (1..n).step_by(2) {
        let event = events
            .iter()
            .find(|e| e.runner_id == i)
            .unwrap_or_else(|| panic!("runner {i} disagreed but was not slashed"));
        let expected = (event.stake_before as f64 * f64::from(fraction)).floor() as Weight;
        assert_eq!(event.slashed, expected, "runner {i} slashed amount");
    }
}

// ────────────────────────────────────────────────────────────────────────
// Property 2 — agreers are NOT slashed.
// ────────────────────────────────────────────────────────────────────────
#[hegel::test]
fn agreement_runners_unslashed(tc: TestCase) {
    let mut ledger = draw_ledger(&tc);
    let n = ledger.len() as u64;
    let consensus = draw_hash(&tc);
    let mut wrong = consensus;
    wrong[0] ^= 0x01;

    let attestations: Vec<Attestation> = (0..n)
        .map(|i| {
            let h = if i % 2 == 0 { consensus } else { wrong };
            make_attestation(i, h)
        })
        .collect();

    // Snapshot the agreers' stakes before.
    let before: Vec<(u64, Weight)> = (0..n).step_by(2).map(|i| (i, ledger.stake_of(i))).collect();

    let events = ledger.slash_minority(consensus, &attestations, 0.5);

    for (i, expected) in before {
        assert_eq!(
            ledger.stake_of(i),
            expected,
            "agreer {i} stake should be unchanged"
        );
        assert!(
            !events.iter().any(|e| e.runner_id == i),
            "agreer {i} appears in slash events"
        );
    }
}

// ────────────────────────────────────────────────────────────────────────
// Property 3 — slashing saturates at zero.
// ────────────────────────────────────────────────────────────────────────
#[hegel::test]
fn slashing_saturates_at_zero(tc: TestCase) {
    let runner_id: u64 = tc.draw(generators::integers::<u64>().min_value(0).max_value(1000));
    let stake: Weight = tc.draw(generators::integers::<Weight>().min_value(1).max_value(100));
    let mut ledger = StakeLedger::new();
    ledger.register(runner_id, stake);

    // Slash by way more than current stake.
    let event = ledger.slash(runner_id, stake * 10);
    assert_eq!(event.stake_after, 0);
    assert_eq!(event.slashed, stake);
    assert_eq!(ledger.stake_of(runner_id), 0);

    // Slash again — already zero, should be a no-op.
    let event2 = ledger.slash(runner_id, 100);
    assert_eq!(event2.stake_before, 0);
    assert_eq!(event2.stake_after, 0);
    assert_eq!(event2.slashed, 0);
}

// ────────────────────────────────────────────────────────────────────────
// Property 4 — fraction > 1.0 clamps to 1.0 (zero out the disagreer).
// ────────────────────────────────────────────────────────────────────────
#[hegel::test]
fn fraction_clamping_above_one_zeros_stake(tc: TestCase) {
    let mut ledger = StakeLedger::new();
    ledger.register(0, 1000);
    ledger.register(1, 1000);

    let consensus = draw_hash(&tc);
    let mut wrong = consensus;
    wrong[0] ^= 0x01;
    let attestations = vec![make_attestation(0, consensus), make_attestation(1, wrong)];

    // fraction = 5.0 should clamp to 1.0
    let oversized: f32 = tc.draw(
        generators::floats::<f32>()
            .min_value(1.0_f32)
            .max_value(100.0_f32),
    );
    ledger.slash_minority(consensus, &attestations, oversized);
    assert_eq!(ledger.stake_of(0), 1000, "agreer untouched");
    assert_eq!(
        ledger.stake_of(1),
        0,
        "disagreer zeroed via clamped fraction"
    );
}

// ────────────────────────────────────────────────────────────────────────
// Property 4 (lower bound) — fraction <= 0.0 is a no-op.
// ────────────────────────────────────────────────────────────────────────
#[hegel::test]
fn fraction_clamping_below_zero_is_noop(tc: TestCase) {
    let mut ledger = StakeLedger::new();
    ledger.register(0, 500);
    ledger.register(1, 500);

    let consensus = draw_hash(&tc);
    let mut wrong = consensus;
    wrong[0] ^= 0x01;
    let attestations = vec![make_attestation(0, consensus), make_attestation(1, wrong)];

    let nonpositive: f32 = tc.draw(
        generators::floats::<f32>()
            .min_value(-100.0_f32)
            .max_value(0.0_f32),
    );
    let events = ledger.slash_minority(consensus, &attestations, nonpositive);
    assert!(events.is_empty(), "non-positive fraction must be a no-op");
    assert_eq!(ledger.stake_of(0), 500);
    assert_eq!(ledger.stake_of(1), 500);
}

// ────────────────────────────────────────────────────────────────────────
// Property 5 — unregistered runners produce no event.
// ────────────────────────────────────────────────────────────────────────
#[hegel::test]
fn unregistered_runner_produces_no_event(tc: TestCase) {
    let mut ledger = StakeLedger::new();
    ledger.register(1, 100);
    // Runner 999 is NOT registered.

    let consensus = draw_hash(&tc);
    let mut wrong = consensus;
    wrong[0] ^= 0x01;
    let attestations = vec![
        make_attestation(1, consensus),
        make_attestation(999, wrong), // unregistered, disagreeing
    ];
    let events = ledger.slash_minority(consensus, &attestations, 0.5);

    assert!(
        events.iter().all(|e| e.runner_id != 999),
        "unregistered runner 999 should produce no slash event"
    );
    assert_eq!(ledger.stake_of(999), 0); // still 0; ledger doesn't grow
}

// ────────────────────────────────────────────────────────────────────────
// Property 6 — ledger state matches events.
// ────────────────────────────────────────────────────────────────────────
#[hegel::test]
fn ledger_state_matches_events(tc: TestCase) {
    let mut ledger = draw_ledger(&tc);
    let n = ledger.len() as u64;
    let consensus = draw_hash(&tc);
    let mut wrong = consensus;
    wrong[0] ^= 0x01;
    let attestations: Vec<Attestation> = (0..n)
        .map(|i| {
            let h = if tc.draw(generators::booleans()) {
                consensus
            } else {
                wrong
            };
            make_attestation(i, h)
        })
        .collect();
    let fraction: f32 = tc.draw(
        generators::floats::<f32>()
            .min_value(0.01_f32)
            .max_value(0.99_f32),
    );
    let events: Vec<SlashEvent> = ledger.slash_minority(consensus, &attestations, fraction);

    for event in &events {
        assert_eq!(
            ledger.stake_of(event.runner_id),
            event.stake_after,
            "ledger.stake_of must match event.stake_after"
        );
    }
}

// ────────────────────────────────────────────────────────────────────────
// Smoke — concrete 4-runner scenario.
// ────────────────────────────────────────────────────────────────────────
#[test]
fn smoke_minority_disagreement() {
    let mut ledger = StakeLedger::new();
    for i in 0..4 {
        ledger.register(i, 100);
    }
    let consensus = [0xaa_u8; 32];
    let wrong = [0xbb_u8; 32];
    let attestations = vec![
        make_attestation(0, consensus), // agreer
        make_attestation(1, consensus), // agreer
        make_attestation(2, consensus), // agreer
        make_attestation(3, wrong),     // disagreer
    ];
    let events = ledger.slash_minority(consensus, &attestations, 0.25);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].runner_id, 3);
    assert_eq!(events[0].stake_before, 100);
    assert_eq!(events[0].stake_after, 75);
    assert_eq!(events[0].slashed, 25);
    // Majority untouched
    assert_eq!(ledger.stake_of(0), 100);
    assert_eq!(ledger.stake_of(1), 100);
    assert_eq!(ledger.stake_of(2), 100);
    assert_eq!(ledger.stake_of(3), 75);
}
