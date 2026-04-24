//! Property-based tests for max-retries enforcement on `Aggregator`.
//!
//! Closes the former `†` sub-claim on `hypotheses/result-aggregation.md`:
//! when `trigger_aggregation` returns `Retry` more than `max_retries`
//! times, the aggregator forces `Escalate` rather than looping forever.

use std::collections::HashMap;

use cosaci::aggregator::{AggregationState, Aggregator};
use cosaci::quorum::{RunnerId, StakeMap, Weight};
use hegel::{TestCase, generators};

/// Build a fleet that, under an empty vote slice, produces `Retry` from
/// `quorum::aggregate` — threshold is reachable (`< total_stake`) and
/// there's unvoted stake.
fn retry_prone_fleet() -> (Weight, StakeMap) {
    let mut stake: StakeMap = HashMap::new();
    for i in 0_u64..5 {
        stake.insert(i as RunnerId, 100);
    }
    // Threshold 300 < total 500 → neither side above 0-weight threshold but
    // unvoted stake (500) could resolve → `Retry`.
    let threshold: Weight = 300;
    (threshold, stake)
}

// ----------------------------------------------------------------------------
// Property 1 — exact boundary. `max_retries` total Retry-triggers keep
// the aggregator `Pending`; the (`max_retries + 1`)-th trigger escalates.
// ----------------------------------------------------------------------------
#[hegel::test]
fn escalates_when_retries_exceed_max(tc: TestCase) {
    let max_retries = tc.draw(generators::integers::<u32>().min_value(0).max_value(20));
    let (threshold, stake) = retry_prone_fleet();
    let mut agg = Aggregator::with_max_retries(threshold, stake, max_retries);

    // First `max_retries` triggers should all keep Pending.
    for i in 0..max_retries {
        let s = agg.trigger_aggregation();
        assert_eq!(
            s,
            AggregationState::Pending,
            "trigger {} escalated too early (max_retries={})",
            i,
            max_retries
        );
    }
    // The (max_retries+1)-th trigger crosses the bound → Escalate.
    let s = agg.trigger_aggregation();
    assert_eq!(
        s,
        AggregationState::Escalate,
        "trigger {} did not escalate at max_retries={}",
        max_retries + 1,
        max_retries
    );
    // Post-Escalate: subsequent triggers remain Escalate (terminal stability).
    let s = agg.trigger_aggregation();
    assert_eq!(s, AggregationState::Escalate);
}

// ----------------------------------------------------------------------------
// Property 2 — `new()` (default constructor) disables max-retries bound.
// Under the default `u32::MAX`, trigger_aggregation never forces Escalate
// from a Retry outcome alone — it stays Pending forever.
// ----------------------------------------------------------------------------
#[hegel::test]
fn default_constructor_does_not_bound_retries(tc: TestCase) {
    let n_triggers = tc.draw(generators::integers::<u32>().min_value(0).max_value(200));
    let (threshold, stake) = retry_prone_fleet();
    let mut agg = Aggregator::new(threshold, stake);

    for _ in 0..n_triggers {
        let s = agg.trigger_aggregation();
        assert_eq!(
            s,
            AggregationState::Pending,
            "default-ctor aggregator unexpectedly escalated at retries={}",
            agg.retries()
        );
    }
    // Retries counter still tracks accurately.
    assert_eq!(agg.retries(), n_triggers);
    assert_eq!(agg.max_retries(), u32::MAX);
}

// ----------------------------------------------------------------------------
// Property 3 — `receive_vote` does NOT consume retry budget. Fresh
// evidence is semantically distinct from an explicit retry.
// ----------------------------------------------------------------------------
#[hegel::test]
fn receive_vote_does_not_increment_retries(tc: TestCase) {
    use cosaci::quorum::{Vote, VoteResult};

    let max_retries = tc.draw(generators::integers::<u32>().min_value(0).max_value(5));
    let (threshold, stake) = retry_prone_fleet();
    let mut agg = Aggregator::with_max_retries(threshold, stake, max_retries);

    // Push a few votes — none should increment retries even if the
    // aggregated outcome is Retry-classified → Pending.
    for i in 0..3 {
        let _ = agg.receive_vote(Vote {
            runner_id: i,
            result: VoteResult::Pass,
        });
        assert_eq!(
            agg.retries(),
            0,
            "receive_vote incremented retry counter (iteration {})",
            i
        );
    }
}
