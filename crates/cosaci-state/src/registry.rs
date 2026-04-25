//! Runner registry.
//!
//! Source: `SPEC.md` §5.2a / `hypotheses/registry-algebra.md` (class A).
//! Tracks which runners are currently eligible to receive leases; exposes
//! `register`, `deregister`, `lookup`, and `is_registered` as the externally
//! observable contract. Lease issuance gates on `is_registered`; actual lease
//! lifecycle is handled in a separate module (see `hypotheses/lease-lifecycle.md`).
//!
//! The `Capabilities` field from SPEC §5.2 is deferred to the
//! `capability-match` card and its module; v0.1 registry stores only the
//! fields required to identify and stake-weight a runner.

use std::collections::HashMap;

/// Identity of a runner in the registry.
pub type RunnerId = u64;

/// State stored per registered runner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunnerInfo {
    /// Ed25519 public key (32 bytes raw).
    pub pubkey: [u8; 32],
    /// Staked weight used by stake-weighted quorum (`hypotheses/quorum-math.md`).
    pub stake: u64,
}

/// In-memory registry of currently-registered runners.
///
/// The registry is the source of truth for "who is eligible to be assigned
/// work right now." It does not persist state; replicas across the coordinator
/// shard are synchronized via the mechanisms covered by
/// `hypotheses/coordinator-shard-algebra.md`.
#[derive(Clone, Debug, Default)]
pub struct Registry {
    runners: HashMap<RunnerId, RunnerInfo>,
}

impl Registry {
    /// Construct an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register or overwrite a runner's info. Last-write-wins if `id` was
    /// previously registered.
    pub fn register(&mut self, id: RunnerId, info: RunnerInfo) {
        self.runners.insert(id, info);
    }

    /// Remove a runner from the registry. No-op (idempotent) if `id` was
    /// not registered.
    pub fn deregister(&mut self, id: RunnerId) {
        self.runners.remove(&id);
    }

    /// Return the info for a registered runner, or `None`.
    #[must_use]
    pub fn lookup(&self, id: RunnerId) -> Option<&RunnerInfo> {
        self.runners.get(&id)
    }

    /// Whether `id` is currently registered. Lease issuance gates on this.
    #[must_use]
    pub fn is_registered(&self, id: RunnerId) -> bool {
        self.runners.contains_key(&id)
    }

    /// Number of currently-registered runners.
    #[must_use]
    pub fn len(&self) -> usize {
        self.runners.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.runners.is_empty()
    }

    /// Iterate over all currently-registered runner ids.
    pub fn ids(&self) -> impl Iterator<Item = RunnerId> + '_ {
        self.runners.keys().copied()
    }
}
