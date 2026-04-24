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
use hegel::{generators, TestCase};

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
    // Model: active_by_job maps each job with a live lease to its id +
    // expiry time. `sync_model` prunes expired entries based on the clock.
    active_by_job: HashMap<u64, (LeaseId, u64)>,
    // Every lease id ever issued by the manager; used to assert uniqueness.
    issued_ids: HashSet<LeaseId>,
}

impl LeaseTest {
    fn sync_model(&mut self) {
        let now = self.clock.now();
        self.active_by_job
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

        let predicted_success = !self.active_by_job.contains_key(&job);
        match self.manager.acquire(job, runner) {
            Ok(lease_id) => {
                assert!(
                    predicted_success,
                    "manager acquired job {} but model said it was leased",
                    job
                );
                assert!(
                    !self.issued_ids.contains(&lease_id),
                    "manager reused lease id {}",
                    lease_id
                );
                self.issued_ids.insert(lease_id);
                self.active_by_job
                    .insert(job, (lease_id, now.saturating_add(TTL_NS)));
            }
            Err(LeaseError::AlreadyLeased) => {
                assert!(
                    !predicted_success,
                    "manager rejected job {} but model said it was free",
                    job
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
        // If this lease_id is the current active lease for some job, remove.
        let job_to_clear: Option<u64> = self
            .active_by_job
            .iter()
            .find(|(_, (lid, _))| *lid == lease_id)
            .map(|(j, _)| *j);
        if let Some(j) = job_to_clear {
            self.active_by_job.remove(&j);
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
        let job_to_clear: Option<u64> = self
            .active_by_job
            .iter()
            .find(|(_, (lid, _))| *lid == lease_id)
            .map(|(j, _)| *j);
        if let Some(j) = job_to_clear {
            self.active_by_job.remove(&j);
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

    // Structural invariant: model and subject agree on per-job active
    // leases, total active count, and uniqueness of lease ids.
    #[invariant]
    fn model_matches_manager(&mut self, _: TestCase) {
        self.sync_model();
        assert_eq!(
            self.manager.count_active(),
            self.active_by_job.len(),
            "active-lease count diverged: manager={}, model={}",
            self.manager.count_active(),
            self.active_by_job.len()
        );
        for (job, (expected_lease, _expires_at)) in self.active_by_job.clone() {
            assert_eq!(
                self.manager.active_lease_for(job),
                Some(expected_lease),
                "active lease for job {} diverged",
                job
            );
            assert!(
                self.manager.is_active(expected_lease),
                "lease {} (job {}) not reported active by manager",
                expected_lease,
                job
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
            self.active_by_job.values().map(|(lid, _)| *lid).collect();
        for &lid in &self.issued_ids.clone() {
            if !currently_active.contains(&lid) {
                let state = self.manager.state_of(lid);
                assert!(
                    matches!(state, Some(LeaseState::Completed) | Some(LeaseState::Expired)),
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
        active_by_job: HashMap::new(),
        issued_ids: HashSet::new(),
    };
    hegel::stateful::run(test, tc);
}
