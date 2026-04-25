//! Stake ledger with minority-disagreement slashing.
//!
//! Source: `SPEC.md` §8.4 / `hypotheses/slashing-faithfulness.md`
//! (issue #35, class A). When the quorum aggregator produces a
//! definitive outcome (Pass or Fail), runners whose attestation
//! diverged from the consensus artifact have their stake slashed by
//! a configurable fraction of their current stake. The majority is
//! untouched.
//!
//! The ledger is in-memory for v0.3; persistence (file-backed Store)
//! is a follow-on PR (issue #51 covers durable runner state more
//! broadly).
//!
//! # Invariants
//!
//! - `stake_of(id)` is monotonically non-increasing for any given
//!   id (slashing only ever decrements). Re-registration is the
//!   only way to add stake; the v0.3 ledger doesn't allow it once
//!   the runner is enrolled.
//! - `slash(id, amount)` saturates at zero — a runner can't owe
//!   stake.
//! - `slash_minority(consensus, attestations, fraction)` is pure:
//!   no I/O, no clock; given the same `(ledger_state, consensus,
//!   attestations, fraction)`, it produces byte-identical
//!   `SlashEvent` lists.

use std::collections::HashMap;

use cosaci_core::attestation::Attestation;
use cosaci_core::quorum::{RunnerId, StakeMap, Weight};

/// In-memory stake ledger. Tracks the current stake for each
/// registered runner and applies slashing events.
#[derive(Clone, Debug, Default)]
pub struct StakeLedger {
    stakes: HashMap<RunnerId, Weight>,
}

/// Record of a single slashing event. Returned from
/// [`StakeLedger::slash_minority`] so callers can log / audit /
/// anchor each event individually.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlashEvent {
    /// Runner whose stake was decremented.
    pub runner_id: RunnerId,
    /// Stake before the slash.
    pub stake_before: Weight,
    /// Stake after the slash (always `<= stake_before`; saturates
    /// at zero).
    pub stake_after: Weight,
    /// Amount actually deducted (`stake_before - stake_after`).
    pub slashed: Weight,
}

impl StakeLedger {
    /// Empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct from an existing `StakeMap` (e.g. the registration
    /// snapshot).
    #[must_use]
    pub fn from_stake_map(stakes: StakeMap) -> Self {
        Self { stakes }
    }

    /// Register a runner with the given initial stake. Overwrites
    /// any existing entry.
    pub fn register(&mut self, runner_id: RunnerId, stake: Weight) {
        self.stakes.insert(runner_id, stake);
    }

    /// Current stake of `runner_id`, or `0` if not enrolled.
    #[must_use]
    pub fn stake_of(&self, runner_id: RunnerId) -> Weight {
        self.stakes.get(&runner_id).copied().unwrap_or(0)
    }

    /// Number of registered runners.
    #[must_use]
    pub fn len(&self) -> usize {
        self.stakes.len()
    }

    /// Whether the ledger holds zero runners.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.stakes.is_empty()
    }

    /// Snapshot the current state as a `StakeMap` (e.g. for passing
    /// to [`cosaci_core::quorum::aggregate`]).
    #[must_use]
    pub fn as_stake_map(&self) -> StakeMap {
        self.stakes.clone()
    }

    /// Slash a single runner by `amount`, saturating at zero. Used
    /// internally; callers should generally prefer
    /// [`Self::slash_minority`].
    pub fn slash(&mut self, runner_id: RunnerId, amount: Weight) -> SlashEvent {
        let before = self.stake_of(runner_id);
        let after = before.saturating_sub(amount);
        self.stakes.insert(runner_id, after);
        SlashEvent {
            runner_id,
            stake_before: before,
            stake_after: after,
            slashed: before - after,
        }
    }

    /// Slash every runner whose attestation's `artifact_hash`
    /// diverges from `consensus_artifact`. Each slashed runner loses
    /// `floor(stake × fraction)` weight, saturating at zero.
    ///
    /// Returns the list of slash events, in the order the
    /// attestations appear in `attestations`. Runners that agree
    /// with the consensus produce no event; runners that don't
    /// appear in the ledger (unenrolled) also produce no event.
    ///
    /// The `fraction` is clamped to `[0.0, 1.0]`. A `fraction` of
    /// `0.0` is a no-op; `1.0` zeros out the disagreer's stake.
    pub fn slash_minority(
        &mut self,
        consensus_artifact: [u8; 32],
        attestations: &[Attestation],
        fraction: f32,
    ) -> Vec<SlashEvent> {
        let f = fraction.clamp(0.0, 1.0);
        let mut events = Vec::new();
        for att in attestations {
            if att.artifact_hash == consensus_artifact {
                continue;
            }
            // Skip runners we don't track. (Could happen if
            // an attestation arrives from an unenrolled runner —
            // the enrollment gate normally prevents this, but the
            // ledger should be defensive.)
            if !self.stakes.contains_key(&att.runner_id) {
                continue;
            }
            let current = self.stake_of(att.runner_id);
            // Use floating-point intermediate then round down — for
            // fraction=0.25 and stake=100 → amount=25.
            let amount: Weight = ((current as f64) * f64::from(f)).floor() as Weight;
            if amount == 0 {
                continue;
            }
            events.push(self.slash(att.runner_id, amount));
        }
        events
    }
}
