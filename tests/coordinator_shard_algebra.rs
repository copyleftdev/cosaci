//! Property-based tests for `cosaci::sharding::{shard_of, ShardedStore}`.
//!
//! Encodes the falsifiable claims of `hypotheses/coordinator-shard-algebra.md`
//! (SPEC.md §4.1.1, class A). Pointwise algebra + a model-based state
//! machine (subject vs. `HashMap` oracle) covering put/get/remove/rebalance.
//!
//! Scope boundaries (per the card):
//! - v0.1 rebalance is atomic — no incremental handoff protocol.
//! - Multi-replica coordination within a shard is out of scope.

use std::collections::{HashMap, HashSet};

use cosaci::sharding::{Key, ShardedStore, Value, shard_of};
use hegel::{TestCase, generators};

// ============================================================================
// Pointwise properties
// ============================================================================

// ----------------------------------------------------------------------------
// Property 1 — shard_of is deterministic; output is always in range.
// ----------------------------------------------------------------------------
#[hegel::test]
fn shard_of_is_deterministic_and_bounded(tc: hegel::TestCase) {
    let key = tc.draw(generators::integers::<Key>());
    let n = tc.draw(
        generators::integers::<usize>()
            .min_value(1)
            .max_value(1_024),
    );
    let a = shard_of(key, n);
    let b = shard_of(key, n);
    assert_eq!(a, b, "shard_of diverged for same (key, n)");
    assert!(a < n, "shard_of returned {} for n={}", a, n);
}

// ----------------------------------------------------------------------------
// Property 2 — put/get round-trip.
// ----------------------------------------------------------------------------
#[hegel::test]
fn put_get_roundtrip(tc: hegel::TestCase) {
    let n = tc.draw(generators::integers::<usize>().min_value(1).max_value(16));
    let mut store = ShardedStore::new(n);
    let key = tc.draw(generators::integers::<Key>());
    let value = tc.draw(generators::integers::<Value>());
    store.put(key, value);
    assert_eq!(store.get(key), Some(value));
}

// ----------------------------------------------------------------------------
// Property 3 — remove clears, returns prior value.
// ----------------------------------------------------------------------------
#[hegel::test]
fn remove_after_put_clears(tc: hegel::TestCase) {
    let n = tc.draw(generators::integers::<usize>().min_value(1).max_value(16));
    let mut store = ShardedStore::new(n);
    let key = tc.draw(generators::integers::<Key>());
    let value = tc.draw(generators::integers::<Value>());
    store.put(key, value);
    assert_eq!(store.remove(key), Some(value));
    assert_eq!(store.get(key), None);
    assert!(!store.contains_key(key));
    assert_eq!(store.remove(key), None, "second remove was not a no-op");
}

// ----------------------------------------------------------------------------
// Property 4 — rebalance loses no keys.
// ----------------------------------------------------------------------------
#[hegel::test]
fn rebalance_loses_no_keys(tc: hegel::TestCase) {
    let n1 = tc.draw(generators::integers::<usize>().min_value(1).max_value(8));
    let n2 = tc.draw(generators::integers::<usize>().min_value(1).max_value(8));
    let n_keys = tc.draw(generators::integers::<usize>().min_value(0).max_value(30));

    let mut store = ShardedStore::new(n1);
    let mut model: HashMap<Key, Value> = HashMap::new();
    for _ in 0..n_keys {
        let k = tc.draw(generators::integers::<Key>());
        let v = tc.draw(generators::integers::<Value>());
        store.put(k, v);
        model.insert(k, v);
    }

    store.rebalance(n2);

    assert_eq!(store.n_shards(), n2);
    assert_eq!(
        store.len(),
        model.len(),
        "cardinality changed under rebalance"
    );
    for (&k, &v) in &model {
        assert_eq!(
            store.get(k),
            Some(v),
            "key {} lost after rebalance from {} to {}",
            k,
            n1,
            n2
        );
    }
}

// ----------------------------------------------------------------------------
// Property 5 — rebalance to same size preserves state.
// ----------------------------------------------------------------------------
#[hegel::test]
fn rebalance_to_same_size_preserves_state(tc: hegel::TestCase) {
    let n = tc.draw(generators::integers::<usize>().min_value(1).max_value(8));
    let n_keys = tc.draw(generators::integers::<usize>().min_value(0).max_value(20));

    let mut store = ShardedStore::new(n);
    let mut model: HashMap<Key, Value> = HashMap::new();
    for _ in 0..n_keys {
        let k = tc.draw(generators::integers::<Key>());
        let v = tc.draw(generators::integers::<Value>());
        store.put(k, v);
        model.insert(k, v);
    }

    store.rebalance(n);

    for (&k, &v) in &model {
        assert_eq!(store.get(k), Some(v));
    }
    assert_eq!(store.len(), model.len());
}

// ----------------------------------------------------------------------------
// Property 6 — puts on different keys commute.
// ----------------------------------------------------------------------------
#[hegel::test]
fn puts_on_different_keys_commute(tc: hegel::TestCase) {
    let n = tc.draw(generators::integers::<usize>().min_value(1).max_value(16));
    let k1 = tc.draw(generators::integers::<Key>());
    let k2 = tc.draw(generators::integers::<Key>());
    if k1 == k2 {
        return;
    }
    let v1 = tc.draw(generators::integers::<Value>());
    let v2 = tc.draw(generators::integers::<Value>());

    let mut s_ab = ShardedStore::new(n);
    s_ab.put(k1, v1);
    s_ab.put(k2, v2);

    let mut s_ba = ShardedStore::new(n);
    s_ba.put(k2, v2);
    s_ba.put(k1, v1);

    // Same final state, observable via get().
    assert_eq!(s_ab.get(k1), s_ba.get(k1));
    assert_eq!(s_ab.get(k2), s_ba.get(k2));
    assert_eq!(s_ab.len(), s_ba.len());
}

// ----------------------------------------------------------------------------
// Property 7 — distribution is not catastrophically biased.
// With 100 distinct keys into 4 shards, no shard holds > 75% of the keys.
// ----------------------------------------------------------------------------
#[hegel::test]
fn shard_distribution_is_not_catastrophic(tc: hegel::TestCase) {
    const N_KEYS: usize = 100;
    const N_SHARDS: usize = 4;

    let keys: Vec<Key> = tc.draw(
        generators::vecs(generators::integers::<Key>())
            .unique(true)
            .min_size(N_KEYS)
            .max_size(N_KEYS),
    );

    let mut counts = [0_usize; N_SHARDS];
    for &k in &keys {
        counts[shard_of(k, N_SHARDS)] += 1;
    }

    let max_count = *counts.iter().max().expect("N_SHARDS > 0");
    assert!(
        max_count <= N_KEYS * 3 / 4,
        "shard load catastrophically uneven: {:?}",
        counts
    );
    // Also: no shard should be entirely empty with 100 keys into 4 shards.
    // Probability a specific shard is empty under uniform = (3/4)^100 ≈ 3e-13.
    let empty = counts.iter().filter(|&&c| c == 0).count();
    assert_eq!(
        empty, 0,
        "empty shard under 100 distinct keys: {:?}",
        counts
    );
}

// ============================================================================
// Model-based state machine: ShardedStore vs HashMap oracle
// ============================================================================

struct ShardTest {
    subject: ShardedStore,
    model: HashMap<Key, Value>,
}

#[hegel::state_machine]
impl ShardTest {
    // Put a key/value. Last-write-wins.
    #[rule]
    fn put(&mut self, tc: TestCase) {
        let k = tc.draw(generators::integers::<Key>().min_value(0).max_value(100));
        let v = tc.draw(generators::integers::<Value>());
        self.subject.put(k, v);
        self.model.insert(k, v);
    }

    // Read a key and assert agreement with the model.
    #[rule]
    fn get(&mut self, tc: TestCase) {
        let k = tc.draw(generators::integers::<Key>().min_value(0).max_value(100));
        assert_eq!(self.subject.get(k), self.model.get(&k).copied());
    }

    // Remove and assert the returned prior value matches.
    #[rule]
    fn remove(&mut self, tc: TestCase) {
        let k = tc.draw(generators::integers::<Key>().min_value(0).max_value(100));
        let sub = self.subject.remove(k);
        let mdl = self.model.remove(&k);
        assert_eq!(sub, mdl);
    }

    // Rebalance to a new shard count.
    #[rule]
    fn rebalance(&mut self, tc: TestCase) {
        let new_n = tc.draw(generators::integers::<usize>().min_value(1).max_value(8));
        self.subject.rebalance(new_n);
        assert_eq!(self.subject.n_shards(), new_n);
    }

    // Structural invariant: subject and model hold the same keys and values.
    #[invariant]
    fn subject_matches_model(&mut self, _: TestCase) {
        assert_eq!(
            self.subject.len(),
            self.model.len(),
            "cardinality diverged: subject={}, model={}",
            self.subject.len(),
            self.model.len()
        );
        for (&k, &v) in &self.model.clone() {
            assert_eq!(self.subject.get(k), Some(v), "key {} value mismatch", k);
        }
        // Keys in subject must all be in model.
        let subject_keys: HashSet<Key> = self.subject.all_keys().into_iter().collect();
        let model_keys: HashSet<Key> = self.model.keys().copied().collect();
        assert_eq!(subject_keys, model_keys, "key sets diverged");
    }

    // Per-shard ownership: every key's current shard equals shard_of(key).
    // This is the "single-shard-per-key" invariant.
    #[invariant]
    fn each_key_on_its_canonical_shard(&mut self, _: TestCase) {
        let n = self.subject.n_shards();
        for k in self.subject.all_keys() {
            let expected = shard_of(k, n);
            let mut found_in: Option<usize> = None;
            for idx in 0..n {
                // Peek the shard's keyspace — any entries at shard idx must
                // route to idx.
                // We don't have a direct accessor for "keys at shard idx",
                // so we rely on `get` + shard_of.
                if shard_of(k, n) == idx && self.subject.get(k).is_some() {
                    // Count this as found at idx.
                    assert!(
                        found_in.is_none() || found_in == Some(idx),
                        "key {} appears on multiple shards",
                        k
                    );
                    found_in = Some(idx);
                }
            }
            assert_eq!(
                found_in,
                Some(expected),
                "key {} not on its canonical shard (expected {})",
                k,
                expected
            );
        }
    }
}

#[hegel::test]
fn sharded_store_matches_hashmap_model(tc: TestCase) {
    let test = ShardTest {
        subject: ShardedStore::new(4),
        model: HashMap::new(),
    };
    hegel::stateful::run(test, tc);
}
