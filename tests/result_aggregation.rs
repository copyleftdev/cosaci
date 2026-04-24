//! Model-based test for `cosaci::aggregator::Aggregator`.
//!
//! Encodes the falsifiable claims of `hypotheses/result-aggregation.md`
//! (SPEC.md §8.2, class A). Wraps the already-passing `quorum::aggregate`
//! with a lifecycle: `Pending → {Pass | Fail | Escalate}`. Terminal states
//! are stable; votes after terminal are ignored; timeout forces terminal.
//!
//! Max-retries sub-claim is deferred (see card frontmatter).

use std::collections::HashMap;

use cosaci::aggregator::{AggregationState, Aggregator};
use cosaci::quorum::{RunnerId, StakeMap, Vote, VoteResult, Weight};
use hegel::{generators, TestCase};

fn draw_vote(tc: &TestCase, ids: &[RunnerId]) -> Vote {
    let i = tc.draw(
        generators::integers::<usize>()
            .min_value(0)
            .max_value(ids.len() - 1),
    );
    let result = if tc.draw(generators::booleans()) {
        VoteResult::Pass
    } else {
        VoteResult::Fail
    };
    Vote {
        runner_id: ids[i],
        result,
    }
}

struct AggregatorTest {
    subject: Aggregator,
    ids: Vec<RunnerId>,
    // Model: record first terminal state if reached.
    ever_terminal: Option<AggregationState>,
    // Model: vote count the aggregator should report.
    expected_vote_count: usize,
}

#[hegel::state_machine]
impl AggregatorTest {
    // Receive a vote. Ignored if terminal.
    #[rule]
    fn receive_vote(&mut self, tc: TestCase) {
        let vote = draw_vote(&tc, &self.ids);
        let was_terminal = self.subject.is_terminal();
        let prev_count = self.subject.vote_count();

        let new_state = self.subject.receive_vote(vote);

        if was_terminal {
            assert_eq!(
                self.subject.vote_count(),
                prev_count,
                "post-terminal vote was counted"
            );
            assert_eq!(
                self.subject.state(),
                self.ever_terminal.unwrap_or(new_state),
                "post-terminal state changed"
            );
        } else {
            self.expected_vote_count += 1;
            assert_eq!(self.subject.vote_count(), self.expected_vote_count);
            if self.subject.is_terminal() && self.ever_terminal.is_none() {
                self.ever_terminal = Some(new_state);
            }
        }
    }

    // Force timeout — always transitions to terminal if not already.
    #[rule]
    fn timeout(&mut self, _tc: TestCase) {
        let was_terminal = self.subject.is_terminal();
        let prev_count = self.subject.vote_count();

        let new_state = self.subject.timeout();

        assert!(self.subject.is_terminal(), "timeout did not force terminal");
        if !was_terminal && self.ever_terminal.is_none() {
            self.ever_terminal = Some(new_state);
        }
        assert_eq!(
            self.subject.vote_count(),
            prev_count,
            "timeout mutated vote count"
        );
    }

    // Terminal stability: once any terminal state was observed, current stays
    // pinned to that state.
    #[invariant]
    fn terminal_is_stable(&mut self, _: TestCase) {
        if let Some(terminal) = self.ever_terminal {
            assert_eq!(
                self.subject.state(),
                terminal,
                "terminal state {:?} was escaped",
                terminal
            );
            assert!(self.subject.is_terminal());
        }
    }

    // Vote-count monotone: count never decreases.
    #[invariant]
    fn vote_count_monotone(&mut self, _: TestCase) {
        assert!(
            self.subject.vote_count() >= self.expected_vote_count
                || self.ever_terminal.is_some(),
            "vote count {} below expected {}",
            self.subject.vote_count(),
            self.expected_vote_count
        );
    }
}

#[hegel::test]
fn aggregator_lifecycle_matches_model(tc: TestCase) {
    // Build a fleet at init. Keep small so quorum thresholds are crossable
    // within Hegel's default rule count.
    let n = tc.draw(generators::integers::<usize>().min_value(2).max_value(6));
    let ids: Vec<RunnerId> = (0..n as RunnerId).collect();
    let mut stake: StakeMap = HashMap::with_capacity(n);
    for &id in &ids {
        let w = tc.draw(
            generators::integers::<Weight>()
                .min_value(1)
                .max_value(10),
        );
        stake.insert(id, w);
    }
    let total_stake: Weight = stake.values().copied().sum();
    // Pick a threshold in [1, total]. Smaller than total/2 means Pass/Fail
    // can both cross; larger than total/2 gives majority-style quorum.
    let threshold = tc.draw(
        generators::integers::<Weight>()
            .min_value(1)
            .max_value(total_stake),
    );

    let test = AggregatorTest {
        subject: Aggregator::new(threshold, stake),
        ids,
        ever_terminal: None,
        expected_vote_count: 0,
    };
    hegel::stateful::run(test, tc);
}
