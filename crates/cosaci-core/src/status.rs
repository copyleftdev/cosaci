//! SCM-visible status lifecycle.
//!
//! Source: `SPEC.md` §11.2 / `hypotheses/status-lifecycle.md` (class A).
//! Defines the external-contract state machine that CosaCI publishes to
//! the SCM (GitHub/GitLab). Internal states (shard migration, vote
//! collection, etc.) aggregate into exactly these four externally.

/// External states published to the SCM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Pending,
    Running,
    QuorumVerifying,
    Success,
    Failure,
}

/// Reasons `transition` can reject a transition attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransitionError {
    /// The `(from, to)` pair is not in the allowed edge set.
    IllegalTransition { from: Status, to: Status },
    /// Attempted to transition out of a terminal state (`Success` or `Failure`).
    AlreadyTerminal { current: Status },
}

/// Whether the edge `from → to` is in the externally-allowed transition set.
///
/// Allowed edges:
/// - `Pending → Running`
/// - `Running → QuorumVerifying`
/// - `QuorumVerifying → Success`
/// - `QuorumVerifying → Failure`
///
/// No other transitions are legal. In particular: no skips (e.g., `Pending →
/// Success`), no backward transitions (e.g., `Running → Pending`), and no
/// egress from `Success` or `Failure`.
#[must_use]
pub fn is_allowed(from: Status, to: Status) -> bool {
    matches!(
        (from, to),
        (Status::Pending, Status::Running)
            | (Status::Running, Status::QuorumVerifying)
            | (Status::QuorumVerifying, Status::Success | Status::Failure)
    )
}

/// Whether `s` is a terminal state.
#[must_use]
pub fn is_terminal(s: Status) -> bool {
    matches!(s, Status::Success | Status::Failure)
}

/// Mutable wrapper that enforces `is_allowed` on every transition.
#[derive(Clone, Copy, Debug)]
pub struct StatusMachine {
    current: Status,
}

impl Default for StatusMachine {
    fn default() -> Self {
        Self {
            current: Status::Pending,
        }
    }
}

impl StatusMachine {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attempt `current → to`. Returns the new state on success.
    ///
    /// # Errors
    ///
    /// Returns `AlreadyTerminal` if the current state is terminal, or
    /// `IllegalTransition` if the edge is not in the allowed set.
    pub fn transition(&mut self, to: Status) -> Result<Status, TransitionError> {
        if is_terminal(self.current) {
            return Err(TransitionError::AlreadyTerminal {
                current: self.current,
            });
        }
        if !is_allowed(self.current, to) {
            return Err(TransitionError::IllegalTransition {
                from: self.current,
                to,
            });
        }
        self.current = to;
        Ok(self.current)
    }

    #[must_use]
    pub fn current(&self) -> Status {
        self.current
    }

    #[must_use]
    pub fn is_terminal(&self) -> bool {
        is_terminal(self.current)
    }
}
