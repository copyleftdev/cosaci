//! Sharded key/value store and routing.
//!
//! Source: `SPEC.md` §4.1.1 / `hypotheses/coordinator-shard-algebra.md`
//! (class A). Tests the **ownership algebra** of sharding + rebalance:
//! routing determinism, rebalance completeness, per-key ownership
//! uniqueness, and commutativity of operations on different keys.
//!
//! v0.1 scope: atomic rebalance, single authoritative state per shard.
//! Two things are explicitly out of scope:
//!
//! 1. **Multi-replica coordination within a shard** (Raft). The card
//!    defers this to production implementation; correctness at the
//!    algebra level does not depend on the replication protocol.
//! 2. **Incremental-handoff rebalance**. v0.1 is atomic: a call to
//!    `rebalance` drains all shards, recreates with the new shard count,
//!    and re-inserts every entry. A phased protocol where keys are
//!    temporarily visible on both source and destination shards is a
//!    future refinement if we find `rebalance` is on the hot path.
//!
//! The partition-invariants † (genuine two-replica split-brain) is
//! NOT subsumed by this card — that concern lives at the replica level
//! within a shard, which v0.1 does not model.

use std::collections::HashMap;

pub type Key = u64;
pub type Value = u64;

/// Shard assignment for a key given a shard count.
///
/// FNV-like mix followed by a finalization step (taken from splitmix64)
/// to break the pathological modular patterns that `key % n_shards` gives
/// on sequential or correlated keys.
///
/// # Panics
///
/// Panics if `n_shards == 0`.
#[must_use]
pub fn shard_of(key: Key, n_shards: usize) -> usize {
    assert!(n_shards > 0, "n_shards must be > 0");
    let mut h = 0xcbf2_9ce4_8422_2325_u64 ^ key;
    h = h.wrapping_mul(0x100000001b3);
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
    h ^= h >> 33;
    (h as usize) % n_shards
}

/// One shard's local state.
#[derive(Clone, Debug, Default)]
pub struct Shard {
    entries: HashMap<Key, Value>,
}

/// Sharded key/value store. Atomically rebalances between shard counts.
#[derive(Clone, Debug)]
pub struct ShardedStore {
    shards: Vec<Shard>,
}

impl ShardedStore {
    /// Construct a store with `n_shards` empty shards. `n_shards` must be > 0.
    ///
    /// # Panics
    ///
    /// Panics if `n_shards == 0`.
    #[must_use]
    pub fn new(n_shards: usize) -> Self {
        assert!(n_shards > 0, "n_shards must be > 0");
        Self {
            shards: (0..n_shards).map(|_| Shard::default()).collect(),
        }
    }

    #[must_use]
    pub fn n_shards(&self) -> usize {
        self.shards.len()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| s.entries.len()).sum()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Put `(key, value)`. Routes to the shard owning `key` at the current
    /// shard count. Last-write-wins.
    pub fn put(&mut self, key: Key, value: Value) {
        let idx = shard_of(key, self.shards.len());
        self.shards[idx].entries.insert(key, value);
    }

    /// Get the current value for `key`, if any.
    #[must_use]
    pub fn get(&self, key: Key) -> Option<Value> {
        let idx = shard_of(key, self.shards.len());
        self.shards[idx].entries.get(&key).copied()
    }

    /// Remove `key`, returning its prior value if any.
    pub fn remove(&mut self, key: Key) -> Option<Value> {
        let idx = shard_of(key, self.shards.len());
        self.shards[idx].entries.remove(&key)
    }

    #[must_use]
    pub fn contains_key(&self, key: Key) -> bool {
        self.get(key).is_some()
    }

    /// Per-shard entry count. `None` if `idx >= n_shards`.
    #[must_use]
    pub fn shard_load(&self, idx: usize) -> Option<usize> {
        self.shards.get(idx).map(|s| s.entries.len())
    }

    /// All currently-held keys, unordered.
    #[must_use]
    pub fn all_keys(&self) -> Vec<Key> {
        self.shards
            .iter()
            .flat_map(|s| s.entries.keys().copied())
            .collect()
    }

    /// Atomic rebalance. Drains every shard, recreates with `new_n`
    /// shards, re-inserts every entry under its new routing.
    ///
    /// # Panics
    ///
    /// Panics if `new_n == 0`.
    pub fn rebalance(&mut self, new_n: usize) {
        assert!(new_n > 0, "new_n must be > 0");
        let mut collected: Vec<(Key, Value)> = Vec::with_capacity(self.len());
        for shard in self.shards.drain(..) {
            collected.extend(shard.entries);
        }
        self.shards = (0..new_n).map(|_| Shard::default()).collect();
        for (k, v) in collected {
            let idx = shard_of(k, new_n);
            self.shards[idx].entries.insert(k, v);
        }
    }
}
