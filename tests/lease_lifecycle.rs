//! Model-based test for `cosaci::lease::LeaseManager`.
//!
//! Encodes the falsifiable claims of `hypotheses/lease-lifecycle.md`
//! (SPEC.md §5.3 + §7.2, class A). Uses `#[hegel::state_machine]` and a
//! test-local `TestClock` (shared `Rc<Cell<u64>>`) to drive deterministic
//! time advancement.
//!
//! First card that exercises the injected-`Clock` path; the `TestClock`
//! pattern here is reused by `replay-protection` and `partition-invariants`.

use std::collections::{HashMap, HashSet};

use cosaci::lease::{LeaseError, LeaseId, LeaseManager, LeaseState};
use hegel::{TestCase, generators};

mod common;
use common::TestClock;

// ----------------------------------------------------------------------------
// Tuning constants for the test. Small enough that Hegel's rule sequences
// reliably exercise expire/reassign transitions within a few hundred rules.
// ----------------------------------------------------------------------------

const TTL_NS: u64 = 1_000_000_000; // 1s of virtual time per lease
const JOB_POOL: u64 = 5; // job ids in [0, JOB_POOL)
const RUNNER_POOL: u64 = 5; // runner ids in [0, RUNNER_POOL)

// ----------------------------------------------------------------------------
// Draw helpers
// ----------------------------------------------------------------------------

fn draw_job(tc: &TestCase) -> u64 {
    tc.draw(
        generators::integers::<u64>()
            .min_value(0)
            .max_value(JOB_POOL - 1),
    )
}

fn draw_runner(tc: &TestCase) -> u64 {
    tc.draw(
        generators::integers::<u64>()
            .min_value(0)
            .max_value(RUNNER_POOL - 1),
    )
}

// ----------------------------------------------------------------------------
// State machine.
// ----------------------------------------------------------------------------

struct LeaseTest {
    clock: TestClock,
    manager: LeaseManager<TestClock>,
    // Model: active_by_pair maps each (job, runner) pair with a live
    // lease to its id + expiry time. `sync_model` prunes expired entries
    // based on the clock.
    active_by_pair: HashMap<(u64, u64), (LeaseId, u64)>,
    // Every lease id ever issued by the manager; used to assert uniqueness.
    issued_ids: HashSet<LeaseId>,
}

impl LeaseTest {
    fn sync_model(&mut self) {
        let now = self.clock.now();
        self.active_by_pair
            .retain(|_, (_lease_id, expires_at)| now < *expires_at);
    }
}

#[hegel::state_machine]
impl LeaseTest {
    // Acquire a lease. Outcome must agree with the model.
    #[rule]
    fn acquire(&mut self, tc: TestCase) {
        self.sync_model();
        let job = draw_job(&tc);
        let runner = draw_runner(&tc);
        let now = self.clock.now();

        let predicted_success = !self.active_by_pair.contains_key(&(job, runner));
        match self.manager.acquire(job, runner) {
            Ok(lease_id) => {
                assert!(
                    predicted_success,
                    "manager acquired ({}, {}) but model said it was leased",
                    job, runner
                );
                assert!(
                    !self.issued_ids.contains(&lease_id),
                    "manager reused lease id {}",
                    lease_id
                );
                self.issued_ids.insert(lease_id);
                self.active_by_pair
                    .insert((job, runner), (lease_id, now.saturating_add(TTL_NS)));
            }
            Err(LeaseError::AlreadyLeased) => {
                assert!(
                    !predicted_success,
                    "manager rejected ({}, {}) but model said it was free",
                    job, runner
                );
            }
        }
    }

    // Complete a lease id drawn broadly; often unknown/expired/completed.
    #[rule]
    fn complete(&mut self, tc: TestCase) {
        self.sync_model();
        let lease_id: LeaseId = tc.draw(
            generators::integers::<LeaseId>()
                .min_value(0)
                .max_value(200),
        );
        let pair_to_clear: Option<(u64, u64)> = self
            .active_by_pair
            .iter()
            .find(|(_, (lid, _))| *lid == lease_id)
            .map(|(p, _)| *p);
        if let Some(p) = pair_to_clear {
            self.active_by_pair.remove(&p);
        }
        self.manager.complete(lease_id);
    }

    // Complete twice in a row — idempotency surface.
    #[rule]
    fn complete_twice(&mut self, tc: TestCase) {
        self.sync_model();
        let lease_id: LeaseId = tc.draw(
            generators::integers::<LeaseId>()
                .min_value(0)
                .max_value(200),
        );
        let pair_to_clear: Option<(u64, u64)> = self
            .active_by_pair
            .iter()
            .find(|(_, (lid, _))| *lid == lease_id)
            .map(|(p, _)| *p);
        if let Some(p) = pair_to_clear {
            self.active_by_pair.remove(&p);
        }
        self.manager.complete(lease_id);
        self.manager.complete(lease_id);
    }

    // Advance the virtual clock; model expires stale leases.
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

    // Structural invariant: model and subject agree on per-pair active
    // leases, total active count, and uniqueness of lease ids.
    #[invariant]
    fn model_matches_manager(&mut self, _: TestCase) {
        self.sync_model();
        assert_eq!(
            self.manager.count_active(),
            self.active_by_pair.len(),
            "active-lease count diverged: manager={}, model={}",
            self.manager.count_active(),
            self.active_by_pair.len()
        );
        for ((job, runner), (expected_lease, _expires_at)) in self.active_by_pair.clone() {
            assert_eq!(
                self.manager.active_lease_for(job, runner),
                Some(expected_lease),
                "active lease for ({}, {}) diverged",
                job,
                runner
            );
            assert!(
                self.manager.is_active(expected_lease),
                "lease {} ({}, {}) not reported active by manager",
                expected_lease,
                job,
                runner
            );
            assert_eq!(
                self.manager.state_of(expected_lease),
                Some(LeaseState::Active),
                "lease {} state diverged from Active",
                expected_lease
            );
        }
        // Spot-check: issued ids that are not currently active in model should
        // report a non-Active state in the manager.
        let currently_active: HashSet<LeaseId> =
            self.active_by_pair.values().map(|(lid, _)| *lid).collect();
        for &lid in &self.issued_ids.clone() {
            if !currently_active.contains(&lid) {
                let state = self.manager.state_of(lid);
                assert!(
                    matches!(
                        state,
                        Some(LeaseState::Completed) | Some(LeaseState::Expired)
                    ),
                    "lease {} should be Completed or Expired, got {:?}",
                    lid,
                    state
                );
            }
        }
    }
}

#[hegel::test]
fn lease_manager_matches_model(tc: TestCase) {
    let clock = TestClock::new();
    let manager = LeaseManager::new(clock.clone(), TTL_NS);
    let test = LeaseTest {
        clock,
        manager,
        active_by_pair: HashMap::new(),
        issued_ids: HashSet::new(),
    };
    hegel::stateful::run(test, tc);
}
