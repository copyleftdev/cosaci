//! Quorum aggregation.
//!
//! Source: `SPEC.md` §8.1 / `hypotheses/quorum-math.md` (class A, load-bearing).
//!
//! `aggregate` collapses a slice of stake-weighted votes into a terminal or
//! transient outcome. Properties are exercised in `tests/quorum_math.rs`.

use std::collections::HashMap;

/// Identity of a runner casting a vote in the quorum.
///
/// v0.1 uses a plain `u64` alias for expedience; a `RunnerId(NonZeroU64)`
/// newtype is the intended next step once the trust chain lands end-to-end.
pub type RunnerId = u64;

/// Voting weight derived from a runner's stake.
///
/// v0.1 uses a plain `u64` alias. At public-infrastructure scale this should
/// become a newtype with saturating arithmetic to prevent overflow when the
/// total staked supply approaches `u64::MAX`.
pub type Weight = u64;

/// Map of `RunnerId` to current voting weight. Runners absent from the map
/// contribute zero weight if they vote.
pub type StakeMap = HashMap<RunnerId, Weight>;

/// A runner's claim about a job's outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VoteResult {
    /// Runner observed the job pass.
    Pass,
    /// Runner observed the job fail.
    Fail,
}

/// One vote submission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vote {
    /// Identifier of the runner casting the vote.
    pub runner_id: RunnerId,
    /// Pass / Fail claim from this runner.
    pub result: VoteResult,
}

/// Quorum outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[must_use]
pub enum Outcome {
    /// Stake-weighted pass votes reached the threshold.
    Pass,
    /// Stake-weighted fail votes reached the threshold. Fail-fast: takes
    /// priority over a simultaneous pass-threshold crossing.
    Fail,
    /// Below threshold; unvoted stake could still carry either side over.
    Retry,
    /// Below threshold and unvoted stake cannot reach threshold on either
    /// side — the vote is structurally unresolvable.
    Escalate,
}

/// Aggregate a vote slice into a quorum outcome.
///
/// Semantics:
///
/// - **Dedup.** Repeated votes from the same `runner_id` collapse to the last
///   entry in slice order (last-write-wins).
/// - **Weighting.** Each surviving vote contributes `stake[runner_id]` to
///   either `pass_weight` or `fail_weight`. Missing stake entries contribute
///   zero.
/// - **Fail-fast.** If `fail_weight >= threshold`, the outcome is `Fail`
///   regardless of `pass_weight`.
/// - **Escalate.** Returned only when `pass_weight + remaining_stake < threshold`
///   *and* `fail_weight + remaining_stake < threshold`, where `remaining_stake`
///   is the unvoted stake in the map.
///
/// See `hypotheses/quorum-math.md` for the full falsifiable property set.
pub fn aggregate(votes: &[Vote], threshold: Weight, stake: &StakeMap) -> Outcome {
    // Last-write-wins dedup by runner_id.
    let mut latest: HashMap<RunnerId, VoteResult> = HashMap::with_capacity(votes.len());
    for v in votes {
        latest.insert(v.runner_id, v.result);
    }

    let mut pass_weight: Weight = 0;
    let mut fail_weight: Weight = 0;
    for (rid, result) in &latest {
        let w = stake.get(rid).copied().unwrap_or(0);
        match result {
            VoteResult::Pass => pass_weight = pass_weight.saturating_add(w),
            VoteResult::Fail => fail_weight = fail_weight.saturating_add(w),
        }
    }

    // Fail-fast takes priority over simultaneous pass-threshold crossing.
    if fail_weight >= threshold {
        return Outcome::Fail;
    }
    if pass_weight >= threshold {
        return Outcome::Pass;
    }

    let total_stake: Weight = stake.values().copied().sum();
    let voted_stake = pass_weight.saturating_add(fail_weight);
    let remaining = total_stake.saturating_sub(voted_stake);

    let pass_reachable = pass_weight.saturating_add(remaining) >= threshold;
    let fail_reachable = fail_weight.saturating_add(remaining) >= threshold;

    if !pass_reachable && !fail_reachable {
        Outcome::Escalate
    } else {
        Outcome::Retry
    }
}
