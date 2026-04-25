//! Runner reputation scoring.
//!
//! Source: `SPEC.md` §8.3a / `hypotheses/reputation-monotonicity.md` (class A).
//! Reputation is a monotone function of a runner's historical agreement rate
//! with quorum outcomes. The monotonicity core (this card) is a pointwise
//! regression guarantee; the adversarial-ranking claim (§8.3b) is B-stat and
//! layers on top.

/// Outcome of one of a runner's prior votes, compared against the quorum's
/// final decision for that job.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgreementOutcome {
    Agree,
    Disagree,
}

/// Reputation assigned to a runner with no recorded history yet. Neutral
/// prior — not the floor (`0.0`) nor the ceiling (`1.0`) so that a new
/// runner is neither trusted nor penalized on entry.
pub const INITIAL_REPUTATION: f64 = 0.5;

/// Fraction of a runner's prior votes that agreed with the quorum outcome.
/// Empty history returns `INITIAL_REPUTATION` so that `reputation` composes
/// cleanly with the monotonicity property regardless of history length.
#[must_use]
pub fn agreement_rate(history: &[AgreementOutcome]) -> f64 {
    if history.is_empty() {
        return INITIAL_REPUTATION;
    }
    let agrees = history
        .iter()
        .filter(|o| **o == AgreementOutcome::Agree)
        .count();
    agrees as f64 / history.len() as f64
}

/// Reputation score in `[0.0, 1.0]`. v0.1 is identity over `agreement_rate`;
/// later versions may apply Wilson scoring, time decay, or stake weighting
/// while preserving the monotonicity property tested in
/// `tests/reputation_monotonicity.rs`.
#[must_use]
pub fn reputation(history: &[AgreementOutcome]) -> f64 {
    agreement_rate(history)
}
