//! Property-based tests for `cosaci::quorum::aggregate`.
//!
//! Encodes the falsifiable claims of `hypotheses/quorum-math.md`
//! (SPEC.md §8.1, class A, load-bearing).

use std::collections::{HashMap, HashSet};

use cosaci::quorum::{aggregate, Outcome, RunnerId, StakeMap, Vote, VoteResult, Weight};
use hegel::generators;

// ----------------------------------------------------------------------------
// Draw helpers
// ----------------------------------------------------------------------------

fn draw_fleet(tc: &hegel::TestCase, n_runners: usize) -> (Vec<RunnerId>, StakeMap) {
    let ids: Vec<RunnerId> = (0..n_runners as RunnerId).collect();
    let mut stake: StakeMap = HashMap::with_capacity(n_runners);
    for &id in &ids {
        let w = tc.draw(
            generators::integers::<Weight>()
                .min_value(1)
                .max_value(100),
        );
        stake.insert(id, w);
    }
    (ids, stake)
}

fn draw_vote_result(tc: &hegel::TestCase) -> VoteResult {
    if tc.draw(generators::booleans()) {
        VoteResult::Pass
    } else {
        VoteResult::Fail
    }
}

/// Draw k unique votes where k ∈ [0, ids.len()]. Each drawn runner appears
/// at most once — suitable for tests that depend on no-dedup semantics.
fn draw_unique_votes(tc: &hegel::TestCase, ids: &[RunnerId]) -> Vec<Vote> {
    let k = tc.draw(
        generators::integers::<usize>()
            .min_value(0)
            .max_value(ids.len()),
    );
    if k == 0 {
        return Vec::new();
    }
    let indices: Vec<usize> = tc.draw(
        generators::vecs(
            generators::integers::<usize>()
                .min_value(0)
                .max_value(ids.len() - 1),
        )
        .unique(true)
        .min_size(k)
        .max_size(k),
    );
    let mut votes = Vec::with_capacity(indices.len());
    for i in indices {
        votes.push(Vote {
            runner_id: ids[i],
            result: draw_vote_result(tc),
        });
    }
    votes
}

/// Draw arbitrary votes (duplicates allowed) over `ids`.
fn draw_any_votes(tc: &hegel::TestCase, ids: &[RunnerId]) -> Vec<Vote> {
    let k = tc.draw(
        generators::integers::<usize>()
            .min_value(0)
            .max_value(50),
    );
    if ids.is_empty() || k == 0 {
        return Vec::new();
    }
    let mut votes = Vec::with_capacity(k);
    for _ in 0..k {
        let i = tc.draw(
            generators::integers::<usize>()
                .min_value(0)
                .max_value(ids.len() - 1),
        );
        votes.push(Vote {
            runner_id: ids[i],
            result: draw_vote_result(tc),
        });
    }
    votes
}

fn draw_threshold(tc: &hegel::TestCase) -> Weight {
    tc.draw(
        generators::integers::<Weight>()
            .min_value(1)
            .max_value(2_000),
    )
}

/// Compute pass/fail weight directly — independent oracle for tests that
/// need to check aggregate's preconditions without calling aggregate itself.
fn compute_weights(votes: &[Vote], stake: &StakeMap) -> (Weight, Weight) {
    let mut latest: HashMap<RunnerId, VoteResult> = HashMap::new();
    for v in votes {
        latest.insert(v.runner_id, v.result);
    }
    let mut pass: Weight = 0;
    let mut fail: Weight = 0;
    for (rid, result) in &latest {
        let w = stake.get(rid).copied().unwrap_or(0);
        match result {
            VoteResult::Pass => pass = pass.saturating_add(w),
            VoteResult::Fail => fail = fail.saturating_add(w),
        }
    }
    (pass, fail)
}

// ----------------------------------------------------------------------------
// Property 1 — order-insensitivity (unique-runner vote sets only).
// ----------------------------------------------------------------------------
#[hegel::test]
fn aggregate_is_order_insensitive(tc: hegel::TestCase) {
    let n = tc.draw(generators::integers::<usize>().min_value(1).max_value(20));
    let (ids, stake) = draw_fleet(&tc, n);
    let votes = draw_unique_votes(&tc, &ids);
    let threshold = draw_threshold(&tc);

    let baseline = aggregate(&votes, threshold, &stake);

    if votes.is_empty() {
        return;
    }
    let perm: Vec<usize> = tc.draw(
        generators::vecs(
            generators::integers::<usize>()
                .min_value(0)
                .max_value(votes.len() - 1),
        )
        .unique(true)
        .min_size(votes.len())
        .max_size(votes.len()),
    );
    let permuted: Vec<Vote> = perm.iter().map(|&i| votes[i]).collect();
    let shuffled = aggregate(&permuted, threshold, &stake);

    assert_eq!(baseline, shuffled, "permutation changed outcome");
}

// ----------------------------------------------------------------------------
// Property 2 — last-write-wins.
// Prepending an earlier duplicate vote (with opposite result) must not change
// the outcome: the later vote wins.
// ----------------------------------------------------------------------------
#[hegel::test]
fn aggregate_last_write_wins(tc: hegel::TestCase) {
    let n = tc.draw(generators::integers::<usize>().min_value(1).max_value(20));
    let (ids, stake) = draw_fleet(&tc, n);
    let votes = draw_unique_votes(&tc, &ids);
    if votes.is_empty() {
        return;
    }
    let threshold = draw_threshold(&tc);
    let baseline = aggregate(&votes, threshold, &stake);

    let victim_idx = tc.draw(
        generators::integers::<usize>()
            .min_value(0)
            .max_value(votes.len() - 1),
    );
    let victim = votes[victim_idx];
    let opposite = match victim.result {
        VoteResult::Pass => VoteResult::Fail,
        VoteResult::Fail => VoteResult::Pass,
    };
    let earlier = Vote {
        runner_id: victim.runner_id,
        result: opposite,
    };
    let mut augmented = Vec::with_capacity(votes.len() + 1);
    augmented.push(earlier);
    augmented.extend_from_slice(&votes);

    let outcome = aggregate(&augmented, threshold, &stake);
    assert_eq!(baseline, outcome, "earlier duplicate vote changed outcome");
}

// ----------------------------------------------------------------------------
// Property 3 — monotone in pass support.
// Adding a Pass vote from a runner not already voting cannot degrade a PASS
// outcome. (Adding from an already-voting runner would be a retraction; see
// property 2 / spec dedup semantics.)
// ----------------------------------------------------------------------------
#[hegel::test]
fn aggregate_monotone_in_pass(tc: hegel::TestCase) {
    let n = tc.draw(generators::integers::<usize>().min_value(2).max_value(20));
    let (ids, stake) = draw_fleet(&tc, n);
    let votes = draw_unique_votes(&tc, &ids);
    let threshold = draw_threshold(&tc);

    let baseline = aggregate(&votes, threshold, &stake);

    let voted: HashSet<RunnerId> = votes.iter().map(|v| v.runner_id).collect();
    let candidates: Vec<RunnerId> = ids
        .iter()
        .copied()
        .filter(|id| !voted.contains(id))
        .collect();
    if candidates.is_empty() {
        return;
    }
    let pick = tc.draw(
        generators::integers::<usize>()
            .min_value(0)
            .max_value(candidates.len() - 1),
    );
    let new_id = candidates[pick];
    let mut augmented = votes.clone();
    augmented.push(Vote {
        runner_id: new_id,
        result: VoteResult::Pass,
    });

    let outcome = aggregate(&augmented, threshold, &stake);
    if baseline == Outcome::Pass {
        assert_eq!(
            outcome,
            Outcome::Pass,
            "adding Pass vote degraded outcome from PASS"
        );
    }
}

// ----------------------------------------------------------------------------
// Property 4 — fail-fast.
// Once fail_weight >= threshold, additional votes from previously-unvoting
// runners cannot change the outcome away from FAIL.
// ----------------------------------------------------------------------------
#[hegel::test]
fn aggregate_is_fail_fast(tc: hegel::TestCase) {
    let n = tc.draw(generators::integers::<usize>().min_value(2).max_value(20));
    let (ids, stake) = draw_fleet(&tc, n);
    let votes = draw_unique_votes(&tc, &ids);
    let threshold = draw_threshold(&tc);

    let baseline = aggregate(&votes, threshold, &stake);
    if baseline != Outcome::Fail {
        return;
    }

    let voted: HashSet<RunnerId> = votes.iter().map(|v| v.runner_id).collect();
    let available: Vec<RunnerId> = ids
        .iter()
        .copied()
        .filter(|id| !voted.contains(id))
        .collect();
    let k = tc.draw(
        generators::integers::<usize>()
            .min_value(0)
            .max_value(available.len()),
    );
    let extra: Vec<Vote> = if k == 0 {
        Vec::new()
    } else {
        let indices: Vec<usize> = tc.draw(
            generators::vecs(
                generators::integers::<usize>()
                    .min_value(0)
                    .max_value(available.len() - 1),
            )
            .unique(true)
            .min_size(k)
            .max_size(k),
        );
        indices
            .into_iter()
            .map(|i| Vote {
                runner_id: available[i],
                result: draw_vote_result(&tc),
            })
            .collect()
    };

    let mut augmented = votes.clone();
    augmented.extend(extra);
    let outcome = aggregate(&augmented, threshold, &stake);

    assert_eq!(
        outcome,
        Outcome::Fail,
        "fresh-runner votes changed outcome away from FAIL"
    );
}

// ----------------------------------------------------------------------------
// Property 5 — empty input is never terminal.
// ----------------------------------------------------------------------------
#[hegel::test]
fn aggregate_empty_input_is_not_terminal(tc: hegel::TestCase) {
    let n = tc.draw(generators::integers::<usize>().min_value(0).max_value(20));
    let (_ids, stake) = draw_fleet(&tc, n);
    let threshold = draw_threshold(&tc);

    let outcome = aggregate(&[], threshold, &stake);
    assert!(
        matches!(outcome, Outcome::Retry | Outcome::Escalate),
        "empty votes produced terminal outcome: {:?}",
        outcome
    );
}

// ----------------------------------------------------------------------------
// Property 6 — below-threshold outcomes are Retry or Escalate.
// Uses the oracle `compute_weights` (structurally simpler than aggregate) to
// determine the precondition, then checks aggregate's output.
// ----------------------------------------------------------------------------
#[hegel::test]
fn aggregate_below_threshold_is_retry_or_escalate(tc: hegel::TestCase) {
    let n = tc.draw(generators::integers::<usize>().min_value(1).max_value(20));
    let (ids, stake) = draw_fleet(&tc, n);
    let votes = draw_any_votes(&tc, &ids);
    let threshold = draw_threshold(&tc);

    let (pass_w, fail_w) = compute_weights(&votes, &stake);
    if pass_w < threshold && fail_w < threshold {
        let outcome = aggregate(&votes, threshold, &stake);
        assert!(
            matches!(outcome, Outcome::Retry | Outcome::Escalate),
            "below-threshold gave {:?} (pass_w={}, fail_w={}, threshold={})",
            outcome,
            pass_w,
            fail_w,
            threshold
        );
    }
}

// ----------------------------------------------------------------------------
// Property 7a — pass_weight exactly at threshold gives PASS (inclusive).
// ----------------------------------------------------------------------------
#[hegel::test]
fn aggregate_exact_pass_threshold_is_pass(tc: hegel::TestCase) {
    let threshold = tc.draw(
        generators::integers::<Weight>()
            .min_value(1)
            .max_value(1_000),
    );
    let mut stake: StakeMap = HashMap::new();
    stake.insert(0_u64, threshold);
    let votes = vec![Vote {
        runner_id: 0,
        result: VoteResult::Pass,
    }];
    assert_eq!(aggregate(&votes, threshold, &stake), Outcome::Pass);
}

// ----------------------------------------------------------------------------
// Property 7b — fail_weight exactly at threshold gives FAIL (inclusive).
// ----------------------------------------------------------------------------
#[hegel::test]
fn aggregate_exact_fail_threshold_is_fail(tc: hegel::TestCase) {
    let threshold = tc.draw(
        generators::integers::<Weight>()
            .min_value(1)
            .max_value(1_000),
    );
    let mut stake: StakeMap = HashMap::new();
    stake.insert(0_u64, threshold);
    let votes = vec![Vote {
        runner_id: 0,
        result: VoteResult::Fail,
    }];
    assert_eq!(aggregate(&votes, threshold, &stake), Outcome::Fail);
}
