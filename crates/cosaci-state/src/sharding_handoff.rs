//! Sharded store with incremental-handoff rebalance.
//!
//! Source: extends `hypotheses/coordinator-shard-algebra.md` — closes
//! the incremental-handoff half of that card's former `†`. Intra-shard
//! Raft coordination remains a production concern outside the Hegel
//! filter's scope.
//!
//! Protocol:
//!
//! - **Stable:** one set of shards. `put` / `get` / `remove` route per
//!   `shard_of(key, n_shards)`.
//! - **Migrating:** the *old* shard set is preserved alongside a freshly
//!   initialized *new* shard set at the new shard count. Reads consult
//!   new shards first and fall back to old if the key hasn't migrated
//!   yet. Writes go to the new shards. `migrate_step(key)` moves one
//!   key from its old-shard location to its new-shard location.
//!   `complete_rebalance` drains all remaining old-shard keys into new
//!   shards and drops the old-shard set.
//!
//! Key claim tested in `tests/shard_incremental_handoff.rs`: at every
//! point during migration, every key that was present before
//! `begin_rebalance` is retrievable via `get`.

use std::collections::HashMap;

use crate::sharding::{Key, Value, shard_of};

/// One shard's entries.
#[derive(Clone, Debug, Default)]
struct Shard {
    entries: HashMap<Key, Value>,
}

/// Sharded store with phased-rebalance support.
pub struct HandoffStore {
    /// Current (post-migration or pre-rebalance) shard set. Always
    /// the authoritative write target.
    new_shards: Vec<Shard>,
    /// Previous shard set, retained during migration so reads can
    /// fall back for keys not yet migrated. `None` when stable.
    old_shards: Option<Vec<Shard>>,
}

fn fresh_shards(n: usize) -> Vec<Shard> {
    (0..n).map(|_| Shard::default()).collect()
}

impl HandoffStore {
    /// Construct a stable store with `n_shards` empty shards.
    ///
    /// # Panics
    ///
    /// Panics if `n_shards == 0`.
    #[must_use]
    pub fn new(n_shards: usize) -> Self {
        assert!(n_shards > 0, "n_shards must be > 0");
        Self {
            new_shards: fresh_shards(n_shards),
            old_shards: None,
        }
    }

    /// Whether a rebalance is in progress.
    #[must_use]
    pub fn is_migrating(&self) -> bool {
        self.old_shards.is_some()
    }

    /// Current (destination) shard count.
    #[must_use]
    pub fn n_shards(&self) -> usize {
        self.new_shards.len()
    }

    /// Put `(key, value)`. Always routes to `new_shards` regardless of
    /// migration state.
    pub fn put(&mut self, key: Key, value: Value) {
        let idx = shard_of(key, self.new_shards.len());
        self.new_shards[idx].entries.insert(key, value);
        // If this key is still sitting in old_shards (never migrated),
        // drop the stale copy now — the authoritative write is on new.
        if let Some(old) = &mut self.old_shards {
            let old_idx = shard_of(key, old.len());
            old[old_idx].entries.remove(&key);
        }
    }

    /// Get `key`. Reads new shards first, falls back to old shards if
    /// a migration is in progress and the key hasn't migrated yet.
    #[must_use]
    pub fn get(&self, key: Key) -> Option<Value> {
        let idx_new = shard_of(key, self.new_shards.len());
        if let Some(&v) = self.new_shards[idx_new].entries.get(&key) {
            return Some(v);
        }
        if let Some(old) = &self.old_shards {
            let idx_old = shard_of(key, old.len());
            if let Some(&v) = old[idx_old].entries.get(&key) {
                return Some(v);
            }
        }
        None
    }

    /// Remove `key`. Clears from both new and old shard sets.
    pub fn remove(&mut self, key: Key) -> Option<Value> {
        let idx_new = shard_of(key, self.new_shards.len());
        let from_new = self.new_shards[idx_new].entries.remove(&key);
        let mut from_old: Option<Value> = None;
        if let Some(old) = &mut self.old_shards {
            let idx_old = shard_of(key, old.len());
            from_old = old[idx_old].entries.remove(&key);
        }
        from_new.or(from_old)
    }

    /// Begin a rebalance to `new_n` shards. Current shards become old;
    /// fresh empty shards take their place. Writes flow to the new set;
    /// reads fall back to old for not-yet-migrated keys.
    ///
    /// # Panics
    ///
    /// Panics if `new_n == 0` or if a rebalance is already in progress.
    pub fn begin_rebalance(&mut self, new_n: usize) {
        assert!(new_n > 0, "new_n must be > 0");
        assert!(self.old_shards.is_none(), "already migrating");
        let prior = std::mem::replace(&mut self.new_shards, fresh_shards(new_n));
        self.old_shards = Some(prior);
    }

    /// Migrate one key from its old-shard location to its new-shard
    /// location. No-op if the key is not in old shards.
    /// Returns true if a migration happened.
    pub fn migrate_step(&mut self, key: Key) -> bool {
        let Some(old) = &mut self.old_shards else {
            return false;
        };
        let idx_old = shard_of(key, old.len());
        let Some(v) = old[idx_old].entries.remove(&key) else {
            return false;
        };
        let idx_new = shard_of(key, self.new_shards.len());
        self.new_shards[idx_new].entries.insert(key, v);
        true
    }

    /// Complete the rebalance: drain all remaining old-shard keys into
    /// new shards, then drop the old shard set.
    pub fn complete_rebalance(&mut self) {
        let Some(old) = self.old_shards.take() else {
            return;
        };
        for shard in old {
            for (k, v) in shard.entries {
                let idx = shard_of(k, self.new_shards.len());
                self.new_shards[idx].entries.insert(k, v);
            }
        }
    }

    /// Total key count across both shard sets (union).
    #[must_use]
    pub fn len(&self) -> usize {
        let new_count: usize = self.new_shards.iter().map(|s| s.entries.len()).sum();
        let old_count: usize = self
            .old_shards
            .as_ref()
            .map_or(0, |old| old.iter().map(|s| s.entries.len()).sum());
        new_count + old_count
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
