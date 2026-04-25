//! Partition-aware lease cluster wrapper.
//!
//! Source: `SPEC.md` §12.3 / `hypotheses/partition-invariants.md` (class A).
//!
//! **v0.1 modeling choice:** single authoritative `LeaseManager` behind a
//! partition gate that rejects operations from the non-majority side while
//! partitioned. This validates the **gating contract** (only majority
//! accepts writes during partition); it does **not** simulate two
//! divergent replicas with reconciliation. Genuine multi-replica
//! split-brain coverage is deferred to the Tier 1
//! `coordinator-shard-algebra` card; under-network faults are
//! `real-partition-recovery` (class C).
//!
//! The "at most one active lease per job" invariant is inherited from
//! `LeaseManager` (already proven in `hypotheses/lease-lifecycle.md`); this
//! module's contribution is that the **gating logic cannot silently admit
//! minority-side writes**.

use crate::clock::Clock;
use crate::lease::{JobId, LeaseError, LeaseId, LeaseManager, RunnerId};

/// Which physical side of a partition a client lives on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    A,
    B,
}

/// Failure modes a cluster operation can return.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClusterError {
    /// Job already has an active lease (passed through from `LeaseManager`).
    AlreadyLeased,
    /// The calling side is not the current partition majority; the
    /// coordinator refuses to accept writes.
    NotAuthoritative,
}

impl From<LeaseError> for ClusterError {
    fn from(e: LeaseError) -> Self {
        match e {
            LeaseError::AlreadyLeased => Self::AlreadyLeased,
        }
    }
}

/// Side-gated wrapper over `LeaseManager`.
pub struct Cluster<C: Clock> {
    manager: LeaseManager<C>,
    /// `None` = connected; `Some(majority)` = partitioned with `majority`
    /// holding authoritative write access.
    partition: Option<Side>,
}

impl<C: Clock> Cluster<C> {
    #[must_use]
    pub fn new(clock: C, ttl_ns: u64) -> Self {
        Self {
            manager: LeaseManager::new(clock, ttl_ns),
            partition: None,
        }
    }

    /// Try to acquire a lease. Rejected with `NotAuthoritative` if `side`
    /// is not the current majority during a partition.
    ///
    /// # Errors
    ///
    /// `ClusterError::NotAuthoritative` if minority-side during partition.
    /// `ClusterError::AlreadyLeased` if the job already has an active lease.
    pub fn acquire(
        &mut self,
        side: Side,
        job: JobId,
        runner: RunnerId,
    ) -> Result<LeaseId, ClusterError> {
        self.authorize(side)?;
        self.manager
            .acquire(job, runner)
            .map_err(ClusterError::from)
    }

    /// Complete a lease. Rejected with `NotAuthoritative` if `side` is not
    /// the current majority during a partition.
    ///
    /// # Errors
    ///
    /// `ClusterError::NotAuthoritative` if minority-side during partition.
    pub fn complete(&mut self, side: Side, lease_id: LeaseId) -> Result<(), ClusterError> {
        self.authorize(side)?;
        self.manager.complete(lease_id);
        Ok(())
    }

    fn authorize(&self, side: Side) -> Result<(), ClusterError> {
        match self.partition {
            Some(majority) if side != majority => Err(ClusterError::NotAuthoritative),
            _ => Ok(()),
        }
    }

    /// Declare a partition with `majority` holding authoritative access.
    /// Idempotent with respect to the same majority.
    pub fn partition(&mut self, majority: Side) {
        self.partition = Some(majority);
    }

    /// Heal the partition. Idempotent.
    pub fn heal(&mut self) {
        self.partition = None;
    }

    /// Current partition majority, or `None` if connected.
    #[must_use]
    pub fn majority(&self) -> Option<Side> {
        self.partition
    }

    /// Whether the cluster is currently partitioned.
    #[must_use]
    pub fn is_partitioned(&self) -> bool {
        self.partition.is_some()
    }

    /// Active lease for the `(job, runner)` pair (passed through).
    pub fn active_lease_for(&mut self, job: JobId, runner: RunnerId) -> Option<LeaseId> {
        self.manager.active_lease_for(job, runner)
    }

    /// Count of active leases across the cluster.
    pub fn count_active(&mut self) -> usize {
        self.manager.count_active()
    }

    /// All currently-active `(job, runner)` pairs.
    pub fn active_pairs(&mut self) -> Vec<(JobId, RunnerId)> {
        self.manager.active_pairs()
    }
}
