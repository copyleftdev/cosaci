//! Lease lifecycle.
//!
//! Source: `SPEC.md` §5.3 + §7.2 / `hypotheses/lease-lifecycle.md` (class A).
//! A lease is a time-bounded token pairing `(job_id, runner_id, lease_id)`.
//! Manages the state machine over acquire / complete / (lazy) expire.
//!
//! Time is injected via the `Clock` trait — never read via
//! `std::time::Instant::now()` inside the manager — to keep the whole
//! subsystem reachable by deterministic simulation.

use std::collections::HashMap;

use cosaci_core::clock::Clock;

pub type JobId = u64;
pub type RunnerId = u64;
pub type LeaseId = u64;

/// Current state of a lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseState {
    Active,
    Completed,
    Expired,
}

/// One lease record.
#[derive(Clone, Copy, Debug)]
pub struct Lease {
    pub lease_id: LeaseId,
    pub job_id: JobId,
    pub runner_id: RunnerId,
    pub acquired_at_ns: u64,
    pub ttl_ns: u64,
    pub state: LeaseState,
}

impl Lease {
    #[must_use]
    pub fn expires_at_ns(&self) -> u64 {
        self.acquired_at_ns.saturating_add(self.ttl_ns)
    }
}

/// Reasons `acquire` can fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseError {
    /// Job already has an active lease; cannot double-issue.
    AlreadyLeased,
}

/// Manages the set of leases for a single shard.
///
/// Lazy expiration: stale leases are swept on every public mutation
/// and on every read-style accessor (`is_active`, `active_lease_for`,
/// `count_active`). This keeps the in-memory state in sync with the
/// injected clock without requiring a background task.
///
/// **Keying:** uniqueness is per `(job_id, runner_id)` pair, not per
/// `job_id` alone. A quorum-based CI assigns committees of K runners to
/// the same job; each pair gets its own lease. To enforce
/// "one runner per job" again, callers can layer that policy on top of
/// `count_active_for_job`.
pub struct LeaseManager<C: Clock> {
    clock: C,
    default_ttl_ns: u64,
    leases: HashMap<LeaseId, Lease>,
    active_by_pair: HashMap<(JobId, RunnerId), LeaseId>,
    next_id: LeaseId,
}

impl<C: Clock> LeaseManager<C> {
    #[must_use]
    pub fn new(clock: C, default_ttl_ns: u64) -> Self {
        Self {
            clock,
            default_ttl_ns,
            leases: HashMap::new(),
            active_by_pair: HashMap::new(),
            next_id: 1,
        }
    }

    /// Attempt to acquire a lease for the `(job_id, runner_id)` pair.
    /// `AlreadyLeased` if that pair already holds an active lease (e.g.,
    /// the same runner was assigned to the same job twice). Multiple
    /// runners can hold simultaneous leases on the same `job_id` —
    /// that's the committee case.
    ///
    /// # Errors
    ///
    /// Returns `LeaseError::AlreadyLeased` if the pair currently holds
    /// an active lease.
    pub fn acquire(&mut self, job_id: JobId, runner_id: RunnerId) -> Result<LeaseId, LeaseError> {
        self.tick();
        let key = (job_id, runner_id);
        if self.active_by_pair.contains_key(&key) {
            return Err(LeaseError::AlreadyLeased);
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let lease = Lease {
            lease_id: id,
            job_id,
            runner_id,
            acquired_at_ns: self.clock.now_ns(),
            ttl_ns: self.default_ttl_ns,
            state: LeaseState::Active,
        };
        self.leases.insert(id, lease);
        self.active_by_pair.insert(key, id);
        Ok(id)
    }

    /// Mark a lease completed. Idempotent: repeated calls on the same
    /// `lease_id` are no-ops. No-op on unknown ids and on expired leases
    /// (no late revival).
    pub fn complete(&mut self, lease_id: LeaseId) {
        self.tick();
        if let Some(lease) = self.leases.get_mut(&lease_id)
            && matches!(lease.state, LeaseState::Active)
        {
            lease.state = LeaseState::Completed;
            self.active_by_pair.remove(&(lease.job_id, lease.runner_id));
        }
    }

    /// Sweep any active leases whose TTL has elapsed according to the
    /// current clock reading.
    fn tick(&mut self) {
        let now = self.clock.now_ns();
        let to_expire: Vec<LeaseId> = self
            .leases
            .iter()
            .filter(|(_, l)| matches!(l.state, LeaseState::Active) && now >= l.expires_at_ns())
            .map(|(&id, _)| id)
            .collect();
        for id in to_expire {
            if let Some(lease) = self.leases.get_mut(&id) {
                lease.state = LeaseState::Expired;
                self.active_by_pair.remove(&(lease.job_id, lease.runner_id));
            }
        }
    }

    /// Whether `lease_id` is currently active (not completed, not expired).
    pub fn is_active(&mut self, lease_id: LeaseId) -> bool {
        self.tick();
        self.leases
            .get(&lease_id)
            .is_some_and(|l| matches!(l.state, LeaseState::Active))
    }

    /// The active lease id for the `(job_id, runner_id)` pair, or `None`.
    pub fn active_lease_for(&mut self, job_id: JobId, runner_id: RunnerId) -> Option<LeaseId> {
        self.tick();
        self.active_by_pair.get(&(job_id, runner_id)).copied()
    }

    /// Number of distinct runners with an active lease for `job_id`.
    pub fn count_active_for_job(&mut self, job_id: JobId) -> usize {
        self.tick();
        self.active_by_pair
            .keys()
            .filter(|(j, _)| *j == job_id)
            .count()
    }

    /// Count of currently-active leases across all `(job, runner)` pairs.
    pub fn count_active(&mut self) -> usize {
        self.tick();
        self.active_by_pair.len()
    }

    /// All currently-active `(job_id, runner_id)` pairs. Useful for tests.
    pub fn active_pairs(&mut self) -> Vec<(JobId, RunnerId)> {
        self.tick();
        self.active_by_pair.keys().copied().collect()
    }

    /// Current state of a lease, or `None` if unknown. Returns authoritative
    /// state after lazy expiry sweep.
    pub fn state_of(&mut self, lease_id: LeaseId) -> Option<LeaseState> {
        self.tick();
        self.leases.get(&lease_id).map(|l| l.state)
    }
}
