//! Two-replica cluster with genuine split-brain semantics.
//!
//! Source: extends `hypotheses/partition-invariants.md` — closes the
//! former `†` on multi-replica split-brain that `src/partition.rs`'s
//! single-state gate did not cover.
//!
//! Semantics:
//!
//! - **Connected:** every `acquire` applies to the target side and then
//!   propagates to the other replica. Barring a prior divergence, the
//!   two replicas stay in sync.
//! - **Partitioned:** propagation stops. Each side operates on its own
//!   `LeaseManager`; both sides can accept writes for overlapping jobs.
//!   This is the genuine split-brain window.
//! - **Heal:** majority wins — the minority replica is reset to an empty
//!   state. Any writes the minority received during partition are
//!   discarded. Subsequent Connected writes propagate to both replicas
//!   starting from the majority's state.
//!
//! This is a **test-oriented model** of the split-brain / reconciliation
//! contract, not a production replication protocol. It exists so the
//! invariant "no persistent split-brain post-heal" has a falsifiable
//! test; a production implementation would use Raft within each shard.

use cosaci_core::clock::Clock;

use crate::lease::{JobId, LeaseError, LeaseManager, RunnerId};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    A,
    B,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClusterError {
    /// Target replica already has an active lease for this job.
    AlreadyLeased,
}

impl From<LeaseError> for ClusterError {
    fn from(e: LeaseError) -> Self {
        match e {
            LeaseError::AlreadyLeased => Self::AlreadyLeased,
        }
    }
}

pub struct TwoReplicaCluster<C: Clock + Clone> {
    replica_a: LeaseManager<C>,
    replica_b: LeaseManager<C>,
    partitioned: bool,
    /// Which side is authoritative when partitioned (reconciliation winner).
    majority: Side,
    clock: C,
    ttl_ns: u64,
}

impl<C: Clock + Clone> TwoReplicaCluster<C> {
    #[must_use]
    pub fn new(clock: C, ttl_ns: u64) -> Self {
        Self {
            replica_a: LeaseManager::new(clock.clone(), ttl_ns),
            replica_b: LeaseManager::new(clock.clone(), ttl_ns),
            partitioned: false,
            majority: Side::A,
            clock,
            ttl_ns,
        }
    }

    /// Acquire a lease on the given `side`. In Connected mode, the
    /// operation propagates to the other replica too (best-effort).
    /// In Partitioned mode, the operation stays local to `side`.
    ///
    /// # Errors
    ///
    /// `ClusterError::AlreadyLeased` if the target replica already has
    /// an active lease for `job`.
    pub fn acquire(
        &mut self,
        side: Side,
        job: JobId,
        runner: RunnerId,
    ) -> Result<(), ClusterError> {
        let result = self.replica_mut(side).acquire(job, runner);

        if !self.partitioned && result.is_ok() {
            // Best-effort replication to the other side. Failure here
            // would indicate prior divergence — ignored in v0.1.
            let _ = self.other_mut(side).acquire(job, runner);
        }

        result.map(|_| ()).map_err(ClusterError::from)
    }

    /// Begin a network partition with `majority` as the reconciliation
    /// winner upon heal.
    pub fn partition(&mut self, majority: Side) {
        self.partitioned = true;
        self.majority = majority;
    }

    /// Heal the partition. Minority replica is reset to empty — any
    /// writes it received during partition are discarded. Majority is
    /// authoritative.
    pub fn heal(&mut self) {
        if self.partitioned {
            let minority = self.other_side(self.majority);
            let fresh = LeaseManager::new(self.clock.clone(), self.ttl_ns);
            *self.replica_mut(minority) = fresh;
        }
        self.partitioned = false;
    }

    #[must_use]
    pub fn is_partitioned(&self) -> bool {
        self.partitioned
    }

    /// Whether replica `side` currently has an active lease for the
    /// `(job, runner)` pair.
    pub fn side_has_active(&mut self, side: Side, job: JobId, runner: RunnerId) -> bool {
        self.replica_mut(side)
            .active_lease_for(job, runner)
            .is_some()
    }

    /// Total active leases across both replicas for the `(job, runner)`
    /// pair. During partition this can be 2 (split brain); in Connected
    /// mode it should be 0 or 2 only because both replicas stay in sync.
    pub fn global_active_count(&mut self, job: JobId, runner: RunnerId) -> usize {
        usize::from(self.side_has_active(Side::A, job, runner))
            + usize::from(self.side_has_active(Side::B, job, runner))
    }

    /// Total distinct active `(job, runner)` pairs for `job`, summed
    /// across both replicas. Useful for "how many committee members
    /// across the whole cluster currently hold an active lease on this
    /// job" — which during partition can exceed the committee size as
    /// split-brain accumulates.
    pub fn global_active_count_for_job(&mut self, job: JobId) -> usize {
        self.replica_a.count_active_for_job(job) + self.replica_b.count_active_for_job(job)
    }

    fn replica_mut(&mut self, side: Side) -> &mut LeaseManager<C> {
        match side {
            Side::A => &mut self.replica_a,
            Side::B => &mut self.replica_b,
        }
    }

    fn other_mut(&mut self, side: Side) -> &mut LeaseManager<C> {
        self.replica_mut(self.other_side(side))
    }

    fn other_side(&self, side: Side) -> Side {
        match side {
            Side::A => Side::B,
            Side::B => Side::A,
        }
    }
}
