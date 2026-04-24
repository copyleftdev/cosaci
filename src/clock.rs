//! Injectable time source.
//!
//! All subsystems that depend on wall time (`lease`, `replay`, future
//! `partition`/`gossip`) route time through this trait. No module should
//! call `std::time::Instant::now()` directly — DST depends on every
//! temporal decision being controllable from a test.

/// Monotonically-increasing clock, injectable for deterministic testing.
///
/// Production builds wrap `std::time::SystemTime` or `Instant`; tests use
/// an in-memory `Cell<u64>` that the test advances explicitly.
pub trait Clock {
    /// Current time in nanoseconds since an implementation-defined epoch.
    fn now_ns(&self) -> u64;
}
