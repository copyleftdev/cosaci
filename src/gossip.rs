//! Anti-entropy gossip over a last-writer-wins (LWW) register CRDT.
//!
//! Source: `SPEC.md` §12.3 / `hypotheses/gossip-convergence-invariant.md`
//! (class A). Pure state-machine algebra — no networking. The merge
//! function is associative, commutative, and idempotent; pairwise gossip
//! rounds using this merge drive divergent replicas to a shared fixpoint
//! in bounded time under no new writes.
//!
//! v0.1 entry shape: `(value: u64, timestamp: u64)` with LWW on
//! timestamp; ties broken by max-value to keep merge deterministic.

use std::collections::HashMap;

pub type Key = u64;
pub type Value = u64;
pub type Timestamp = u64;

/// One value, tagged with a logical timestamp for LWW resolution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub value: Value,
    pub timestamp: Timestamp,
}

/// Per-node state: one LWW entry per key.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct NodeState {
    entries: HashMap<Key, Entry>,
}

impl NodeState {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply a local write. LWW on timestamp; tie-broken by max-value.
    pub fn write(&mut self, key: Key, value: Value, timestamp: Timestamp) {
        let incoming = Entry { value, timestamp };
        let keep_existing = match self.entries.get(&key) {
            Some(existing) => entry_dominates(*existing, incoming),
            None => false,
        };
        if !keep_existing {
            self.entries.insert(key, incoming);
        }
    }

    pub fn get(&self, key: Key) -> Option<Entry> {
        self.entries.get(&key).copied()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn keys(&self) -> impl Iterator<Item = Key> + '_ {
        self.entries.keys().copied()
    }
}

/// Does `a` dominate `b` (i.e., should a `merge(b→a)` keep `a`)?
/// Strictly: `a.timestamp > b.timestamp`, or equal timestamp with
/// `a.value >= b.value`. Non-strict on tie to make the relation a
/// total preorder for determinism.
fn entry_dominates(a: Entry, b: Entry) -> bool {
    if a.timestamp != b.timestamp {
        a.timestamp > b.timestamp
    } else {
        a.value >= b.value
    }
}

/// Merge two node states. Output is deterministic in inputs: same
/// `(a, b)` always produces the same result; `merge(a, b) == merge(b, a)`;
/// `merge(a, merge(b, c)) == merge(merge(a, b), c)`; `merge(a, a) == a`.
#[must_use]
pub fn merge(a: &NodeState, b: &NodeState) -> NodeState {
    let mut out = a.clone();
    for (&k, &entry_b) in &b.entries {
        let winner = match out.entries.get(&k).copied() {
            Some(entry_a) => {
                if entry_dominates(entry_a, entry_b) {
                    entry_a
                } else {
                    entry_b
                }
            }
            None => entry_b,
        };
        out.entries.insert(k, winner);
    }
    out
}
