//! Model-based test for `cosaci::partition::Cluster`.
//!
//! Encodes the falsifiable claims of `hypotheses/partition-invariants.md`
//! (SPEC.md §12.3, class A). **v0.1 covers only the partition-gating
//! contract** — that minority-side operations during partition consistently
//! return `NotAuthoritative`, and that the global "at most one active lease
//! per job" invariant (inherited from `LeaseManager`) continues to hold
//! across arbitrary partition/heal/op sequences.

use std::collections::{HashMap, HashSet};

use cosaci::lease::LeaseId;
use cosaci::partition::{Cluster, ClusterError, Side};
use hegel::{TestCase, generators};

mod common;
use common::TestClock;

const TTL_NS: u64 = 1_000_000_000;
const JOB_POOL: u64 = 5;
const RUNNER_POOL: u64 = 5;

fn draw_side(tc: &TestCase) -> Side {
    if tc.draw(generators::booleans()) {
        Side::A
    } else {
        Side::B
    }
}

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

struct PartitionTest {
    clock: TestClock,
    subject: Cluster<TestClock>,
    // Model: per-(job, runner) active leases and expiry.
    active_by_pair: HashMap<(u64, u64), (LeaseId, u64)>,
    // Set of all lease ids ever issued by the subject (uniqueness check).
    issued_ids: HashSet<LeaseId>,
}

impl PartitionTest {
    fn sync_model(&mut self) {
        let now = self.clock.now();
        self.active_by_pair
            .retain(|_, (_, expires_at)| now < *expires_at);
    }
}

#[hegel::state_machine]
impl PartitionTest {
    // Acquire. Outcome must match (a) partition gate + (b) model's prediction.
    #[rule]
    fn acquire(&mut self, tc: TestCase) {
        self.sync_model();
        let side = draw_side(&tc);
        let job = draw_job(&tc);
        let runner = draw_runner(&tc);
        let now = self.clock.now();

        let majority = self.subject.majority();
        let is_minority_op = majority.is_some_and(|m| m != side);
        let model_says_free = !self.active_by_pair.contains_key(&(job, runner));

        match self.subject.acquire(side, job, runner) {
            Ok(lease_id) => {
                assert!(
                    !is_minority_op,
                    "cluster accepted minority-side acquire during partition"
                );
                assert!(
                    model_says_free,
                    "cluster accepted acquire for already-leased ({}, {})",
                    job, runner
                );
                assert!(
                    !self.issued_ids.contains(&lease_id),
                    "cluster reused lease id {}",
                    lease_id
                );
                self.issued_ids.insert(lease_id);
                self.active_by_pair
                    .insert((job, runner), (lease_id, now.saturating_add(TTL_NS)));
            }
            Err(ClusterError::NotAuthoritative) => {
                assert!(
                    is_minority_op,
                    "cluster rejected non-minority acquire with NotAuthoritative"
                );
            }
            Err(ClusterError::AlreadyLeased) => {
                assert!(
                    !model_says_free,
                    "cluster rejected free ({}, {}) as AlreadyLeased",
                    job, runner
                );
                assert!(
                    !is_minority_op,
                    "minority-side acquire got AlreadyLeased instead of NotAuthoritative"
                );
            }
        }
    }

    // Complete. Gated identically to acquire.
    #[rule]
    fn complete(&mut self, tc: TestCase) {
        self.sync_model();
        let side = draw_side(&tc);
        let lease_id: LeaseId = tc.draw(
            generators::integers::<LeaseId>()
                .min_value(0)
                .max_value(200),
        );

        let majority = self.subject.majority();
        let is_minority_op = majority.is_some_and(|m| m != side);

        match self.subject.complete(side, lease_id) {
            Ok(()) => {
                assert!(
                    !is_minority_op,
                    "cluster accepted minority-side complete during partition"
                );
                let pair_to_clear: Option<(u64, u64)> = self
                    .active_by_pair
                    .iter()
                    .find(|(_, (lid, _))| *lid == lease_id)
                    .map(|(p, _)| *p);
                if let Some(p) = pair_to_clear {
                    self.active_by_pair.remove(&p);
                }
            }
            Err(ClusterError::NotAuthoritative) => {
                assert!(
                    is_minority_op,
                    "cluster rejected non-minority complete with NotAuthoritative"
                );
            }
            Err(ClusterError::AlreadyLeased) => {
                panic!("complete() should never return AlreadyLeased");
            }
        }
    }

    // Declare a partition.
    #[rule]
    fn partition_op(&mut self, tc: TestCase) {
        let majority = draw_side(&tc);
        self.subject.partition(majority);
    }

    // Heal the partition.
    #[rule]
    fn heal(&mut self, _tc: TestCase) {
        self.subject.heal();
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

    // Invariant: subject's active-lease state matches model.
    #[invariant]
    fn uniqueness_holds(&mut self, _: TestCase) {
        self.sync_model();
        assert_eq!(
            self.subject.count_active(),
            self.active_by_pair.len(),
            "active-lease count diverged: subject={}, model={}",
            self.subject.count_active(),
            self.active_by_pair.len()
        );
        for (&(job, runner), &(expected_lease, _)) in &self.active_by_pair.clone() {
            assert_eq!(
                self.subject.active_lease_for(job, runner),
                Some(expected_lease),
                "active lease diverged for ({}, {})",
                job,
                runner
            );
        }
    }
}

#[hegel::test]
fn cluster_gating_holds_under_partitions(tc: TestCase) {
    let clock = TestClock::new();
    let subject = Cluster::new(clock.clone(), TTL_NS);
    let test = PartitionTest {
        clock,
        subject,
        active_by_pair: HashMap::new(),
        issued_ids: HashSet::new(),
    };
    hegel::stateful::run(test, tc);
}
