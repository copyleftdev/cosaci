//! Property-based tests for `cosaci::sharding_handoff::HandoffStore`.
//!
//! Closes the incremental-handoff half of the former `†` on
//! `hypotheses/coordinator-shard-algebra.md`. During a rebalance, keys
//! stay readable via the destination shard set (with fallback to source
//! for not-yet-migrated keys) and no key is lost across the phased
//! transition.
//!
//! Intra-shard Raft (the other half of the original `†`) remains a
//! production concern — that would require an actual Raft implementation
//! and is orthogonal to the incremental-handoff claim tested here.

use std::collections::{HashMap, HashSet};

use cosaci::sharding::{Key, Value};
use cosaci::sharding_handoff::HandoffStore;
use hegel::generators;

// ----------------------------------------------------------------------------
// Pointwise properties
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// Property 1 — during migration, every pre-rebalance key remains readable.
// ----------------------------------------------------------------------------
#[hegel::test]
fn keys_remain_readable_during_migration(tc: hegel::TestCase) {
    let n1 = tc.draw(generators::integers::<usize>().min_value(1).max_value(8));
    let n2 = tc.draw(generators::integers::<usize>().min_value(1).max_value(8));
    let n_keys = tc.draw(generators::integers::<usize>().min_value(0).max_value(25));

    let mut store = HandoffStore::new(n1);
    let mut inserted: HashMap<Key, Value> = HashMap::new();
    for _ in 0..n_keys {
        let k = tc.draw(generators::integers::<Key>());
        let v = tc.draw(generators::integers::<Value>());
        store.put(k, v);
        inserted.insert(k, v);
    }

    store.begin_rebalance(n2);
    assert!(store.is_migrating());
    assert_eq!(store.n_shards(), n2);

    // Every key written pre-rebalance is still readable mid-migration.
    for (&k, &v) in &inserted {
        assert_eq!(
            store.get(k),
            Some(v),
            "key {} lost during migration (n1={}, n2={})",
            k,
            n1,
            n2
        );
    }
}

// ----------------------------------------------------------------------------
// Property 2 — mid-migration writes take effect via the new shard set.
// ----------------------------------------------------------------------------
#[hegel::test]
fn writes_during_migration_are_visible(tc: hegel::TestCase) {
    let n1 = tc.draw(generators::integers::<usize>().min_value(1).max_value(8));
    let n2 = tc.draw(generators::integers::<usize>().min_value(1).max_value(8));

    let mut store = HandoffStore::new(n1);
    store.begin_rebalance(n2);

    let k = tc.draw(generators::integers::<Key>());
    let v = tc.draw(generators::integers::<Value>());
    store.put(k, v);
    assert_eq!(store.get(k), Some(v));
}

// ----------------------------------------------------------------------------
// Property 3 — migrating an already-written key doesn't change its value.
// ----------------------------------------------------------------------------
#[hegel::test]
fn migrate_step_preserves_value(tc: hegel::TestCase) {
    let n1 = tc.draw(generators::integers::<usize>().min_value(1).max_value(8));
    let n2 = tc.draw(generators::integers::<usize>().min_value(1).max_value(8));

    let mut store = HandoffStore::new(n1);
    let k = tc.draw(generators::integers::<Key>());
    let v = tc.draw(generators::integers::<Value>());
    store.put(k, v);

    store.begin_rebalance(n2);
    let migrated = store.migrate_step(k);
    assert!(migrated, "migrate_step did not move key {}", k);
    assert_eq!(store.get(k), Some(v), "value changed under migration");
}

// ----------------------------------------------------------------------------
// Property 4 — complete_rebalance drains old shards; no key lost.
// ----------------------------------------------------------------------------
#[hegel::test]
fn complete_rebalance_loses_no_keys(tc: hegel::TestCase) {
    let n1 = tc.draw(generators::integers::<usize>().min_value(1).max_value(8));
    let n2 = tc.draw(generators::integers::<usize>().min_value(1).max_value(8));
    let n_keys = tc.draw(generators::integers::<usize>().min_value(0).max_value(25));

    let mut store = HandoffStore::new(n1);
    let mut model: HashMap<Key, Value> = HashMap::new();
    for _ in 0..n_keys {
        let k = tc.draw(generators::integers::<Key>());
        let v = tc.draw(generators::integers::<Value>());
        store.put(k, v);
        model.insert(k, v);
    }

    store.begin_rebalance(n2);

    // Optional: partial migration of some keys before completing.
    let partial_count = tc.draw(
        generators::integers::<usize>()
            .min_value(0)
            .max_value(model.len().max(1)),
    );
    for (i, &k) in model.keys().enumerate() {
        if i >= partial_count {
            break;
        }
        store.migrate_step(k);
    }

    store.complete_rebalance();
    assert!(!store.is_migrating());

    for (&k, &v) in &model {
        assert_eq!(
            store.get(k),
            Some(v),
            "key {} lost after complete_rebalance",
            k
        );
    }
    assert_eq!(store.len(), model.len());
}

// ----------------------------------------------------------------------------
// Property 5 — remove works across both shard sets during migration.
// ----------------------------------------------------------------------------
#[hegel::test]
fn remove_during_migration_clears_both_sets(tc: hegel::TestCase) {
    let n1 = tc.draw(generators::integers::<usize>().min_value(1).max_value(8));
    let n2 = tc.draw(generators::integers::<usize>().min_value(1).max_value(8));

    let mut store = HandoffStore::new(n1);
    let k = tc.draw(generators::integers::<Key>());
    let v = tc.draw(generators::integers::<Value>());
    store.put(k, v);

    store.begin_rebalance(n2);
    // Key is in old shards; remove() should find and clear it.
    let removed = store.remove(k);
    assert_eq!(removed, Some(v));
    assert_eq!(store.get(k), None);
}

// ----------------------------------------------------------------------------
// Property 6 — writes during migration are not duplicated in old shards.
// ----------------------------------------------------------------------------
#[hegel::test]
fn write_during_migration_clears_stale_old_copy(tc: hegel::TestCase) {
    let n1 = tc.draw(generators::integers::<usize>().min_value(1).max_value(8));
    let n2 = tc.draw(generators::integers::<usize>().min_value(1).max_value(8));

    let mut store = HandoffStore::new(n1);
    let k = tc.draw(generators::integers::<Key>());
    let v1 = tc.draw(generators::integers::<Value>());
    store.put(k, v1);

    store.begin_rebalance(n2);
    // Write a new value during migration.
    let v2 = tc.draw(generators::integers::<Value>());
    store.put(k, v2);
    // get() must return the latest write, not the stale old-shard value.
    assert_eq!(store.get(k), Some(v2));
    // After complete_rebalance, still latest value.
    store.complete_rebalance();
    assert_eq!(store.get(k), Some(v2));
}

// ----------------------------------------------------------------------------
// Pointwise union cardinality — len() is monotonic across migration.
// ----------------------------------------------------------------------------
#[hegel::test]
fn len_unchanged_by_begin_and_complete(tc: hegel::TestCase) {
    let n1 = tc.draw(generators::integers::<usize>().min_value(1).max_value(8));
    let n2 = tc.draw(generators::integers::<usize>().min_value(1).max_value(8));
    let n_keys = tc.draw(generators::integers::<usize>().min_value(0).max_value(20));

    let mut store = HandoffStore::new(n1);
    let mut seen: HashSet<Key> = HashSet::new();
    for _ in 0..n_keys {
        let k = tc.draw(generators::integers::<Key>());
        let v = tc.draw(generators::integers::<Value>());
        store.put(k, v);
        seen.insert(k);
    }
    let pre = store.len();
    store.begin_rebalance(n2);
    assert_eq!(store.len(), pre, "len changed on begin_rebalance");
    store.complete_rebalance();
    assert_eq!(store.len(), pre, "len changed on complete_rebalance");
    assert_eq!(store.len(), seen.len());
}
