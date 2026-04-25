//! Property tests for `cosaci-state::partial_quorum`.
//!
//! Encodes the falsifiable claims of
//! `hypotheses/partial-committee-tolerance.md` (issue #61, class A).

use std::collections::HashSet;

use cosaci::partial_quorum::{resolve_with_dropouts, stake_map_from_pairs, two_thirds_threshold};
use cosaci::quorum::{Outcome, RunnerId, Vote, VoteResult, Weight, aggregate};
use hegel::{TestCase, generators};

// ────────────────────────────────────────────────────────────────────────
// Hegel generators
// ────────────────────────────────────────────────────────────────────────

fn draw_committee(tc: &TestCase) -> Vec<RunnerId> {
    let n = tc.draw(generators::integers::<usize>().min_value(1).max_value(8));
    (0..n).map(|i| i as RunnerId).collect()
}

fn draw_stakes(tc: &TestCase, committee: &[RunnerId]) -> Vec<(RunnerId, Weight)> {
    committee
        .iter()
        .map(|&id| {
            let w: Weight = tc.draw(
                generators::integers::<Weight>()
                    .min_value(1)
                    .max_value(1000),
            );
            (id, w)
        })
        .collect()
}

/// Draw a random subset of the committee that responds, with a
/// random Pass/Fail vote for each.
fn draw_partial_votes(tc: &TestCase, committee: &[RunnerId]) -> Vec<Vote> {
    let mut out = Vec::new();
    for &id in committee {
        if tc.draw(generators::booleans()) {
            let result = if tc.draw(generators::booleans()) {
                VoteResult::Pass
            } else {
                VoteResult::Fail
            };
            out.push(Vote {
                runner_id: id,
                result,
            });
        }
    }
    out
}

// ────────────────────────────────────────────────────────────────────────
// Property 1 — responding ∪ missing == committee, ∩ == ∅.
// ────────────────────────────────────────────────────────────────────────
#[hegel::test]
fn responding_and_missing_partition_committee(tc: TestCase) {
    let committee = draw_committee(&tc);
    if committee.is_empty() {
        return;
    }
    let stakes = draw_stakes(&tc, &committee);
    let votes = draw_partial_votes(&tc, &committee);
    let stake_map = stake_map_from_pairs(&stakes);

    let result = resolve_with_dropouts(&committee, &votes, &stake_map, two_thirds_threshold);

    let resp: HashSet<RunnerId> = result.responding.iter().copied().collect();
    let miss: HashSet<RunnerId> = result.missing.iter().copied().collect();
    let union: HashSet<RunnerId> = resp.union(&miss).copied().collect();
    let cm: HashSet<RunnerId> = committee.iter().copied().collect();

    assert!(
        resp.is_disjoint(&miss),
        "responding ∩ missing must be empty"
    );
    assert_eq!(union, cm, "responding ∪ missing must equal committee");
    assert_eq!(
        result.responding.len() + result.missing.len(),
        committee.len(),
        "no duplicates in either list"
    );
}

// ────────────────────────────────────────────────────────────────────────
// Property 2 — outcome equals subset aggregate.
// ────────────────────────────────────────────────────────────────────────
#[hegel::test]
fn outcome_equals_subset_aggregate(tc: TestCase) {
    let committee = draw_committee(&tc);
    if committee.is_empty() {
        return;
    }
    let stakes = draw_stakes(&tc, &committee);
    let votes = draw_partial_votes(&tc, &committee);
    let stake_map = stake_map_from_pairs(&stakes);

    let result = resolve_with_dropouts(&committee, &votes, &stake_map, two_thirds_threshold);

    let independent_outcome = aggregate(&votes, result.threshold, &stake_map);
    assert_eq!(
        result.outcome, independent_outcome,
        "resolve_with_dropouts.outcome must equal aggregate(votes, threshold, _)"
    );
}

// ────────────────────────────────────────────────────────────────────────
// Property 3 — committee of 3, one drops, still resolves.
// ────────────────────────────────────────────────────────────────────────
#[hegel::test]
fn single_failure_in_committee_of_three_yields_outcome(tc: TestCase) {
    let committee = vec![0_u64, 1, 2];
    let stakes = vec![(0_u64, 100), (1, 100), (2, 100)];
    let stake_map = stake_map_from_pairs(&stakes);

    // Two of the three respond; their votes are drawn. The third
    // is silent.
    let dropping = tc.draw(generators::integers::<usize>().min_value(0).max_value(2));
    let votes: Vec<Vote> = (0..3_u64)
        .filter(|&id| id as usize != dropping)
        .map(|id| Vote {
            runner_id: id,
            result: if tc.draw(generators::booleans()) {
                VoteResult::Pass
            } else {
                VoteResult::Fail
            },
        })
        .collect();

    let result = resolve_with_dropouts(&committee, &votes, &stake_map, two_thirds_threshold);
    assert_eq!(result.responding.len(), 2);
    assert_eq!(result.missing.len(), 1);
    assert_eq!(result.missing[0] as usize, dropping);
    // Outcome is well-defined (one of the variants).
    assert!(matches!(
        result.outcome,
        Outcome::Pass | Outcome::Fail | Outcome::Retry | Outcome::Escalate
    ));
}

// ────────────────────────────────────────────────────────────────────────
// Property 4 — threshold uses responding stake.
// ────────────────────────────────────────────────────────────────────────
#[hegel::test]
fn threshold_uses_responding_stake_not_committee_stake(tc: TestCase) {
    let committee = vec![0_u64, 1, 2];
    let stakes = vec![(0_u64, 100), (1, 100), (2, 100)];
    let stake_map = stake_map_from_pairs(&stakes);

    // One runner responds (Pass). The other two are silent.
    let responder = tc.draw(generators::integers::<u64>().min_value(0).max_value(2));
    let votes = vec![Vote {
        runner_id: responder,
        result: VoteResult::Pass,
    }];

    let result = resolve_with_dropouts(&committee, &votes, &stake_map, two_thirds_threshold);
    // Responding stake is just the responder's 100, so threshold is
    // ceil(100 * 2 / 3) = 67. The single Pass vote is 100, which
    // exceeds 67 → Outcome::Pass.
    assert_eq!(result.responding_stake, 100);
    assert_eq!(result.threshold, two_thirds_threshold(100));
    assert_eq!(result.outcome, Outcome::Pass);

    // Compare against what the full-committee threshold would have
    // been. ceil(300 * 2 / 3) = 200. A Pass vote of 100 fails to
    // reach 200 → Outcome::Escalate (or Fail). The correct
    // partial-tolerance behavior is Pass; the wrong behavior is
    // Escalate.
    let full_threshold = two_thirds_threshold(300);
    let wrong_outcome = aggregate(&votes, full_threshold, &stake_map);
    // Pass under partial-stake threshold (correct), but NOT Pass
    // under full-committee threshold (wrong). Use this to encode
    // that the threshold computation matters.
    assert_eq!(result.outcome, Outcome::Pass);
    assert_ne!(
        wrong_outcome,
        Outcome::Pass,
        "responding-stake vs full-committee threshold must produce different outcomes for a single Pass voter"
    );
}

// ────────────────────────────────────────────────────────────────────────
// Property 5 — empty response is handled.
// ────────────────────────────────────────────────────────────────────────
#[hegel::test]
fn empty_response_does_not_panic(tc: TestCase) {
    let committee = draw_committee(&tc);
    let stakes = draw_stakes(&tc, &committee);
    let stake_map = stake_map_from_pairs(&stakes);
    let votes: Vec<Vote> = Vec::new();

    let result = resolve_with_dropouts(&committee, &votes, &stake_map, two_thirds_threshold);
    assert!(result.responding.is_empty());
    assert_eq!(result.missing.len(), committee.len());
    assert_eq!(result.responding_stake, 0);
    // outcome whatever aggregate(&[], 0, _) produces — the property
    // is just that no panic happens.
    let _ = result.outcome;
}

// ────────────────────────────────────────────────────────────────────────
// Smoke — deterministic 3-runner scenario, runner 1 drops.
// ────────────────────────────────────────────────────────────────────────
#[test]
fn smoke_three_runners_one_drops() {
    let committee = vec![0_u64, 1, 2];
    let stakes = vec![(0_u64, 100), (1, 100), (2, 100)];
    let stake_map = stake_map_from_pairs(&stakes);

    // Runners 0 and 2 vote Pass; runner 1 is silent.
    let votes = vec![
        Vote {
            runner_id: 0,
            result: VoteResult::Pass,
        },
        Vote {
            runner_id: 2,
            result: VoteResult::Pass,
        },
    ];
    let result = resolve_with_dropouts(&committee, &votes, &stake_map, two_thirds_threshold);
    assert_eq!(result.responding, vec![0, 2]);
    assert_eq!(result.missing, vec![1]);
    assert_eq!(result.responding_stake, 200);
    // 2/3 of 200 = ceil(133.33) = 134; two Pass votes of weight 100
    // each = 200, which exceeds 134 → Pass.
    assert_eq!(result.threshold, 134);
    assert_eq!(result.outcome, Outcome::Pass);
}
