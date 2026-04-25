//! Partial-committee quorum resolution.
//!
//! Source: `SPEC.md` §8.5 / `hypotheses/partial-committee-tolerance.md`
//! (issue #61, class A). When a committee member fails to respond
//! within the per-runner deadline, their vote is missing from the
//! aggregator's input. The job should still produce a deterministic
//! outcome computed against the responding subset, with the missing
//! runners recorded for downstream reputation accounting.
//!
//! The historical behavior was to `?`-bail the whole job on any
//! single I/O error. In a fleet of laptops that wake/sleep/reconnect,
//! that's a regression magnet — a single dropped TCP connection
//! tanks the whole committee. This module makes the partial path
//! first-class.

use std::collections::{HashMap, HashSet};

use cosaci_core::quorum::{Outcome, RunnerId, StakeMap, Vote, Weight, aggregate};

/// Result of resolving a job under partial-response conditions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartialOutcome {
    /// The aggregated outcome from the responding subset.
    pub outcome: Outcome,
    /// Committee members who responded (in the same order as
    /// `votes`, by `runner_id`).
    pub responding: Vec<RunnerId>,
    /// Committee members who did NOT respond — recorded for the
    /// reputation tracker / log.
    pub missing: Vec<RunnerId>,
    /// Sum of stake the responding members carried into the round.
    pub responding_stake: Weight,
    /// The threshold that was applied.
    pub threshold: Weight,
}

/// Resolve a job's outcome from a (possibly incomplete) attestation
/// set against the original committee.
///
/// - `committee`: every runner who was asked to attest.
/// - `votes`: votes from the runners who actually responded
///   (`votes.len() <= committee.len()`).
/// - `stake_map`: voting weight per runner. Runners not in the map
///   contribute 0.
/// - `threshold_fn`: how the threshold is computed from the
///   *responding* committee's stake. Typical choice:
///   `|s| (s * 2).div_ceil(3)` — 2/3 weighted majority of who
///   actually showed up.
///
/// Pure: no I/O, no clock. Two callers with identical
/// `(committee, votes, stake_map, threshold_fn)` produce identical
/// `PartialOutcome` values.
#[must_use]
pub fn resolve_with_dropouts(
    committee: &[RunnerId],
    votes: &[Vote],
    stake_map: &StakeMap,
    threshold_fn: impl Fn(Weight) -> Weight,
) -> PartialOutcome {
    let responded: HashSet<RunnerId> = votes.iter().map(|v| v.runner_id).collect();

    // Preserve committee-input order for stable Vec outputs.
    let mut responding = Vec::new();
    let mut missing = Vec::new();
    for &id in committee {
        if responded.contains(&id) {
            responding.push(id);
        } else {
            missing.push(id);
        }
    }

    let responding_stake: Weight = responding
        .iter()
        .map(|id| stake_map.get(id).copied().unwrap_or(0))
        .sum();
    let threshold = threshold_fn(responding_stake);
    let outcome = aggregate(votes, threshold, stake_map);

    PartialOutcome {
        outcome,
        responding,
        missing,
        responding_stake,
        threshold,
    }
}

/// Convenience: 2/3-weighted threshold over the responding stake.
#[must_use]
pub fn two_thirds_threshold(responding_stake: Weight) -> Weight {
    (responding_stake * 2).div_ceil(3)
}

/// Build a stake snapshot map from a slice of `(runner_id, stake)`
/// pairs. Convenience for tests + callers that maintain stakes
/// inline rather than in a separate ledger.
#[must_use]
pub fn stake_map_from_pairs(pairs: &[(RunnerId, Weight)]) -> StakeMap {
    let mut m: StakeMap = HashMap::with_capacity(pairs.len());
    for &(id, w) in pairs {
        m.insert(id, w);
    }
    m
}
