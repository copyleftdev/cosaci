//! Replay protection via (nonce, timestamp) + Clock-bounded window.
//!
//! Source: `SPEC.md` §9.1 / `hypotheses/replay-protection.md` (class A).
//! A message is accepted iff its timestamp is within `ttl_ns` of the
//! coordinator's current clock **and** its nonce has not been seen within
//! the `ttl_ns` sliding window. Past-TTL nonces are garbage-collected and
//! become reusable.
//!
//! v0.1 uses `HashMap<u64, u64>` as the nonce index. At public-infrastructure
//! scale, this must move to a bloom filter with a documented false-positive
//! rate — that is a sub-claim deferred to a future dedicated card. The
//! uniqueness-within-window property proved here is format-agnostic and
//! carries over to the bloom variant.

use std::collections::HashMap;

use cosaci_core::clock::Clock;

/// Reasons `accept` can reject a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceptError {
    /// The message's timestamp is more than `ttl_ns` from the current clock
    /// (in either direction). Rejected before the nonce is even checked.
    StaleTimestamp,
    /// The nonce has been accepted within the active window. Rejected.
    Replay,
}

/// Guards a stream of `(nonce, timestamp)` submissions against replay.
///
/// Every successful `accept` records the nonce with the current clock
/// reading; subsequent `accept` calls with the same nonce are rejected
/// until `ttl_ns` elapses, after which the nonce is swept and can be
/// reused.
pub struct ReplayGuard<C: Clock> {
    clock: C,
    ttl_ns: u64,
    /// Nonce → wall-clock time (ns) of first acceptance.
    accepted: HashMap<u64, u64>,
}

impl<C: Clock> ReplayGuard<C> {
    /// Construct a replay guard with the given clock and replay-window
    /// TTL in nanoseconds.
    #[must_use]
    pub fn new(clock: C, ttl_ns: u64) -> Self {
        Self {
            clock,
            ttl_ns,
            accepted: HashMap::new(),
        }
    }

    /// Attempt to accept a message. Sweeps stale nonces first; returns
    /// `Ok(())` on success, `Err(StaleTimestamp)` if the message's timestamp
    /// is too far from the current clock, or `Err(Replay)` if the nonce is
    /// currently in the window.
    ///
    /// # Errors
    ///
    /// Returns `AcceptError::StaleTimestamp` or `AcceptError::Replay` as
    /// documented above.
    pub fn accept(&mut self, nonce: u64, timestamp_ns: u64) -> Result<(), AcceptError> {
        self.sweep();
        let now = self.clock.now_ns();
        let age = now.abs_diff(timestamp_ns);
        if age > self.ttl_ns {
            return Err(AcceptError::StaleTimestamp);
        }
        if self.accepted.contains_key(&nonce) {
            return Err(AcceptError::Replay);
        }
        self.accepted.insert(nonce, now);
        Ok(())
    }

    /// Sweep any nonces whose acceptance time is more than `ttl_ns` in the
    /// past relative to the current clock.
    fn sweep(&mut self) {
        let now = self.clock.now_ns();
        let ttl = self.ttl_ns;
        self.accepted
            .retain(|_, accepted_at| now.saturating_sub(*accepted_at) < ttl);
    }

    /// Whether the nonce is currently in the active window.
    pub fn is_known(&mut self, nonce: u64) -> bool {
        self.sweep();
        self.accepted.contains_key(&nonce)
    }

    /// Number of nonces currently in the active window.
    pub fn count(&mut self) -> usize {
        self.sweep();
        self.accepted.len()
    }
}
