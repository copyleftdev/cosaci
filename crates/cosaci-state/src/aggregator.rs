//! Vote-aggregation lifecycle over the pure `quorum::aggregate` function.
//!
//! Source: `SPEC.md` §8.2 / `hypotheses/result-aggregation.md` (class A).
//! Wraps `quorum::aggregate` with a stateful collector. `Retry` from the
//! pure function maps back to `Pending` here — the lifecycle stays open
//! until a terminal outcome is reached or the coordinator times out.
//!
//! **Max-retries enforcement** (2026-04-24, closes former `†` deferral):
//! `trigger_aggregation` is the explicit re-aggregation entrypoint (e.g.,
//! driven by a timer). Each call that returns `Retry` from the pure
//! function increments an internal counter; once the counter exceeds
//! `max_retries`, the aggregator forces `Escalate`. The default `new`
//! constructor disables this (by setting `max_retries = u32::MAX`) so
//! existing call sites keep their prior semantics.

use cosaci_core::quorum::{self, Outcome as QuorumOutcome, StakeMap, Vote, Weight};

/// Externally-visible state of an aggregating job.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AggregationState {
    /// Still collecting votes.
    Pending,
    /// Pass quorum reached.
    Pass,
    /// Fail quorum reached.
    Fail,
    /// Structurally unresolvable or forced by timeout / retry-budget-exhausted.
    Escalate,
}

/// Stateful wrapper around `quorum::aggregate`.
pub struct Aggregator {
    state: AggregationState,
    votes: Vec<Vote>,
    threshold: Weight,
    stake: StakeMap,
    retries: u32,
    max_retries: u32,
}

impl Aggregator {
    /// Default constructor — max-retries enforcement disabled.
    #[must_use]
    pub fn new(threshold: Weight, stake: StakeMap) -> Self {
        Self::with_max_retries(threshold, stake, u32::MAX)
    }

    /// Constructor with explicit `max_retries`. Once `trigger_aggregation`
    /// has returned `Retry` outcomes more than `max_retries` times, the
    /// aggregator forces `Escalate`.
    #[must_use]
    pub fn with_max_retries(threshold: Weight, stake: StakeMap, max_retries: u32) -> Self {
        Self {
            state: AggregationState::Pending,
            votes: Vec::new(),
            threshold,
            stake,
            retries: 0,
            max_retries,
        }
    }

    /// Append a vote and re-run quorum aggregation. Ignored if terminal.
    /// Does not increment the retry counter — a vote is fresh evidence,
    /// not a retry.
    pub fn receive_vote(&mut self, vote: Vote) -> AggregationState {
        if self.is_terminal() {
            return self.state;
        }
        self.votes.push(vote);
        self.state = match quorum::aggregate(&self.votes, self.threshold, &self.stake) {
            QuorumOutcome::Pass => AggregationState::Pass,
            QuorumOutcome::Fail => AggregationState::Fail,
            QuorumOutcome::Escalate => AggregationState::Escalate,
            QuorumOutcome::Retry => AggregationState::Pending,
        };
        self.state
    }

    /// Explicit re-aggregation (no new evidence; driven by a timer or
    /// external tick). Increments the retry counter when the pure
    /// function returns `Retry`; once counter exceeds `max_retries`,
    /// forces `Escalate`.
    pub fn trigger_aggregation(&mut self) -> AggregationState {
        if self.is_terminal() {
            return self.state;
        }
        self.state = match quorum::aggregate(&self.votes, self.threshold, &self.stake) {
            QuorumOutcome::Pass => AggregationState::Pass,
            QuorumOutcome::Fail => AggregationState::Fail,
            QuorumOutcome::Escalate => AggregationState::Escalate,
            QuorumOutcome::Retry => {
                self.retries = self.retries.saturating_add(1);
                if self.retries > self.max_retries {
                    AggregationState::Escalate
                } else {
                    AggregationState::Pending
                }
            }
        };
        self.state
    }

    /// Force terminal resolution. If the current vote slice already resolves
    /// Pass/Fail, that is the outcome; otherwise the aggregator escalates.
    /// Ignored if already terminal.
    pub fn timeout(&mut self) -> AggregationState {
        if self.is_terminal() {
            return self.state;
        }
        self.state = match quorum::aggregate(&self.votes, self.threshold, &self.stake) {
            QuorumOutcome::Pass => AggregationState::Pass,
            QuorumOutcome::Fail => AggregationState::Fail,
            _ => AggregationState::Escalate,
        };
        self.state
    }

    /// Externally-visible state.
    #[must_use]
    pub fn state(&self) -> AggregationState {
        self.state
    }

    /// Whether the aggregator has reached a terminal state.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            AggregationState::Pass | AggregationState::Fail | AggregationState::Escalate
        )
    }

    /// Number of votes received so far (post-terminal votes are not counted).
    #[must_use]
    pub fn vote_count(&self) -> usize {
        self.votes.len()
    }

    /// Number of retry rounds the aggregator has consumed.
    #[must_use]
    pub fn retries(&self) -> u32 {
        self.retries
    }

    /// Configured retry budget; once `retries() > max_retries()` the
    /// aggregator forces `Escalate`.
    #[must_use]
    pub fn max_retries(&self) -> u32 {
        self.max_retries
    }
}
