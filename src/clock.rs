//! Injectable time source.
//!
//! All subsystems that depend on wall time (`lease`, `replay`, future
//! `partition`/`gossip`) route time through this trait. No module should
//! call `std::time::Instant::now()` directly — DST depends on every
//! temporal decision being controllable from a test.

use std::time::{SystemTime, UNIX_EPOCH};

/// Monotonically-increasing clock, injectable for deterministic testing.
///
/// Production builds wrap `std::time::SystemTime` or `Instant`; tests use
/// an in-memory `Cell<u64>` that the test advances explicitly.
pub trait Clock {
    /// Current time in nanoseconds since an implementation-defined epoch.
    fn now_ns(&self) -> u64;
}

/// Wall-clock implementation backed by `SystemTime::now()`. Non-monotonic
/// under system clock adjustments; for deterministic tests use the
/// `TestClock` pattern in `tests/common/mod.rs` instead.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ns(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }
}
