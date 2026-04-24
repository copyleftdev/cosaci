//! Shared helpers for CosaCI integration tests.
//!
//! Integration-test crates in `tests/*.rs` each `mod common;` this file.
//! Cargo recognizes `tests/common/mod.rs` as a shared helper (not itself
//! an integration test) because it lives in a subdirectory.

#![allow(dead_code)] // individual test files use subsets of the helpers

use std::cell::Cell;
use std::rc::Rc;

use cosaci::clock::Clock;

/// Deterministic in-memory clock. `Rc<Cell<u64>>` inside so `Clone` is
/// cheap and the test can hold one handle while passing another to the
/// subject under test — both see the same shared reading.
#[derive(Clone)]
pub struct TestClock {
    time: Rc<Cell<u64>>,
}

impl TestClock {
    pub fn new() -> Self {
        Self {
            time: Rc::new(Cell::new(0)),
        }
    }

    pub fn advance(&self, ns: u64) {
        self.time.set(self.time.get().saturating_add(ns));
    }

    pub fn now(&self) -> u64 {
        self.time.get()
    }
}

impl Default for TestClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for TestClock {
    fn now_ns(&self) -> u64 {
        self.time.get()
    }
}
