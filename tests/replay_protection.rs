//! Model-based test for `cosaci::replay::ReplayGuard`.
//!
//! Encodes the falsifiable claims of `hypotheses/replay-protection.md`
//! (SPEC.md §9.1, class A). Reuses the `TestClock` pattern introduced by
//! `tests/lease_lifecycle.rs`.
//!
//! The bloom-false-positive sub-claim is not exercised here — v0.1 uses a
//! `HashMap` nonce index and the bloom variant is deferred to a future card.

use std::collections::{HashMap, HashSet};

use cosaci::replay::{AcceptError, ReplayGuard};
use hegel::{TestCase, generators};

mod common;
use common::TestClock;

const TTL_NS: u64 = 1_000_000_000; // 1s virtual
const NONCE_POOL: u64 = 8; // keep small so replays actually happen

fn draw_nonce(tc: &TestCase) -> u64 {
    tc.draw(
        generators::integers::<u64>()
            .min_value(0)
            .max_value(NONCE_POOL - 1),
    )
}

/// Draw a timestamp plausibly near the current clock — span ±3*TTL so we
/// exercise both "fresh" and "stale" paths densely.
fn draw_timestamp(tc: &TestCase, now: u64) -> u64 {
    let offset = tc.draw(
        generators::integers::<u64>()
            .min_value(0)
            .max_value(TTL_NS.saturating_mul(3)),
    );
    let negative = tc.draw(generators::booleans());
    if negative {
        now.saturating_sub(offset)
    } else {
        now.saturating_add(offset)
    }
}

struct ReplayTest {
    clock: TestClock,
    guard: ReplayGuard<TestClock>,
    /// Model: nonce → time (ns) of first-acceptance.
    accepted: HashMap<u64, u64>,
    /// Every nonce ever accepted (for the "post-TTL reuse" property).
    ever_seen: HashSet<u64>,
}

impl ReplayTest {
    fn sync_model(&mut self) {
        let now = self.clock.now();
        self.accepted
            .retain(|_, accepted_at| now.saturating_sub(*accepted_at) < TTL_NS);
    }
}

#[hegel::state_machine]
impl ReplayTest {
    // Try to accept a (nonce, timestamp). Outcome must match the model's
    // prediction based on (a) timestamp freshness and (b) nonce membership.
    #[rule]
    fn try_accept(&mut self, tc: TestCase) {
        self.sync_model();
        let nonce = draw_nonce(&tc);
        let now = self.clock.now();
        let timestamp = draw_timestamp(&tc, now);

        let age = now.abs_diff(timestamp);
        let stale = age > TTL_NS;
        let replay = self.accepted.contains_key(&nonce);

        match self.guard.accept(nonce, timestamp) {
            Ok(()) => {
                assert!(
                    !stale,
                    "accept succeeded on stale timestamp (age={}, ttl={})",
                    age, TTL_NS
                );
                assert!(!replay, "accept succeeded on replayed nonce {}", nonce);
                self.accepted.insert(nonce, now);
                self.ever_seen.insert(nonce);
            }
            Err(AcceptError::StaleTimestamp) => {
                assert!(
                    stale,
                    "rejected fresh timestamp as stale: age={} ttl={}",
                    age, TTL_NS
                );
            }
            Err(AcceptError::Replay) => {
                assert!(
                    replay,
                    "rejected unique nonce as replay: nonce={}, accepted={:?}",
                    nonce, self.accepted
                );
                assert!(!stale, "should not reach replay check with stale timestamp");
            }
        }
    }

    // Force an in-window replay attempt on a known nonce.
    // This makes Hegel exercise the replay-reject path densely without
    // waiting for serendipitous rule sequencing.
    #[rule]
    fn attempt_replay_of_known(&mut self, tc: TestCase) {
        self.sync_model();
        let known: Vec<u64> = self.accepted.keys().copied().collect();
        tc.assume(!known.is_empty());
        let pick = tc.draw(
            generators::integers::<usize>()
                .min_value(0)
                .max_value(known.len() - 1),
        );
        let nonce = known[pick];
        let now = self.clock.now();
        let result = self.guard.accept(nonce, now);
        assert_eq!(
            result,
            Err(AcceptError::Replay),
            "in-window replay of known nonce {} not rejected",
            nonce
        );
    }

    // Force a post-TTL reuse scenario: accept a nonce, advance clock past
    // TTL, accept same nonce again. Second must succeed.
    #[rule]
    fn reuse_nonce_after_ttl(&mut self, tc: TestCase) {
        self.sync_model();
        let nonce = draw_nonce(&tc);
        // Require nonce currently free.
        tc.assume(!self.accepted.contains_key(&nonce));
        let now1 = self.clock.now();
        let r1 = self.guard.accept(nonce, now1);
        tc.assume(r1.is_ok());
        self.accepted.insert(nonce, now1);
        self.ever_seen.insert(nonce);

        self.clock.advance(TTL_NS.saturating_add(1));
        self.sync_model();

        let now2 = self.clock.now();
        let r2 = self.guard.accept(nonce, now2);
        assert_eq!(
            r2,
            Ok(()),
            "post-TTL reuse of nonce {} rejected (now1={}, now2={}, ttl={})",
            nonce,
            now1,
            now2,
            TTL_NS
        );
        self.accepted.insert(nonce, now2);
    }

    // Advance the virtual clock.
    #[rule]
    fn advance_clock(&mut self, tc: TestCase) {
        let delta = tc.draw(
            generators::integers::<u64>()
                .min_value(1)
                .max_value(TTL_NS.saturating_mul(3)),
        );
        self.clock.advance(delta);
        self.sync_model();
    }

    #[invariant]
    fn model_matches_guard(&mut self, _: TestCase) {
        self.sync_model();
        assert_eq!(
            self.guard.count(),
            self.accepted.len(),
            "nonce-window cardinality diverged: guard={}, model={}",
            self.guard.count(),
            self.accepted.len()
        );
        for &nonce in &self.accepted.keys().copied().collect::<Vec<_>>() {
            assert!(
                self.guard.is_known(nonce),
                "nonce {} missing from guard but present in model",
                nonce
            );
        }
        // Nonces that have been seen but dropped from the model should NOT
        // be reported as known.
        let model_keys: HashSet<u64> = self.accepted.keys().copied().collect();
        for &nonce in &self.ever_seen.clone() {
            if !model_keys.contains(&nonce) {
                assert!(
                    !self.guard.is_known(nonce),
                    "nonce {} should have aged out of guard",
                    nonce
                );
            }
        }
    }
}

#[hegel::test]
fn replay_guard_matches_model(tc: TestCase) {
    let clock = TestClock::new();
    let guard = ReplayGuard::new(clock.clone(), TTL_NS);
    let test = ReplayTest {
        clock,
        guard,
        accepted: HashMap::new(),
        ever_seen: HashSet::new(),
    };
    hegel::stateful::run(test, tc);
}
