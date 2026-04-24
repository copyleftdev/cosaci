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
use hegel::{generators, TestCase};

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
    // Model: which jobs currently have an active lease and when they expire.
    active_by_job: HashMap<u64, (LeaseId, u64)>,
    // Set of all lease ids ever issued by the subject (uniqueness check).
    issued_ids: HashSet<LeaseId>,
}

impl PartitionTest {
    fn sync_model(&mut self) {
        let now = self.clock.now();
        self.active_by_job
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
        let model_says_free = !self.active_by_job.contains_key(&job);

        match self.subject.acquire(side, job, runner) {
            Ok(lease_id) => {
                assert!(
                    !is_minority_op,
                    "cluster accepted minority-side acquire during partition"
                );
                assert!(
                    model_says_free,
                    "cluster accepted acquire for already-leased job {}",
                    job
                );
                assert!(
                    !self.issued_ids.contains(&lease_id),
                    "cluster reused lease id {}",
                    lease_id
                );
                self.issued_ids.insert(lease_id);
                self.active_by_job
                    .insert(job, (lease_id, now.saturating_add(TTL_NS)));
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
                    "cluster rejected free job {} as AlreadyLeased",
                    job
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
                // If this lease_id was active for some job in the model,
                // remove it.
                let job_to_clear: Option<u64> = self
                    .active_by_job
                    .iter()
                    .find(|(_, (lid, _))| *lid == lease_id)
                    .map(|(j, _)| *j);
                if let Some(j) = job_to_clear {
                    self.active_by_job.remove(&j);
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
            self.active_by_job.len(),
            "active-lease count diverged: subject={}, model={}",
            self.subject.count_active(),
            self.active_by_job.len()
        );
        for (&job, &(expected_lease, _)) in &self.active_by_job.clone() {
            assert_eq!(
                self.subject.active_lease_for(job),
                Some(expected_lease),
                "active lease diverged for job {}",
                job
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
        active_by_job: HashMap::new(),
        issued_ids: HashSet::new(),
    };
    hegel::stateful::run(test, tc);
}
