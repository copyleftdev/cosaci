//! Property-based tests for `cosaci::gossip`.
//!
//! Encodes the falsifiable claims of `hypotheses/gossip-convergence-invariant.md`
//! (SPEC.md §12.3, class A). Pure algebra: CRDT merge properties +
//! bounded-round convergence on simulated gossip.
//!
//! Propagation *time* (vs merely convergence) is the B-stat
//! `gossip-propagation-time` card in Tier 2; we don't touch it here.

use cosaci::gossip::{Key, NodeState, Timestamp, Value, merge};
use hegel::{TestCase, generators};

// ----------------------------------------------------------------------------
// Draw helpers
// ----------------------------------------------------------------------------

fn draw_state(tc: &TestCase) -> NodeState {
    let n = tc.draw(generators::integers::<usize>().min_value(0).max_value(8));
    let mut s = NodeState::new();
    for _ in 0..n {
        let k = tc.draw(generators::integers::<Key>().min_value(0).max_value(10));
        let v = tc.draw(generators::integers::<Value>().max_value(1_000));
        let t = tc.draw(generators::integers::<Timestamp>().max_value(1_000));
        s.write(k, v, t);
    }
    s
}

// ----------------------------------------------------------------------------
// Property 1 — merge is idempotent: merge(s, s) == s.
// ----------------------------------------------------------------------------
#[hegel::test]
fn merge_is_idempotent(tc: hegel::TestCase) {
    let s = draw_state(&tc);
    assert_eq!(merge(&s, &s), s, "merge(s, s) diverged from s");
}

// ----------------------------------------------------------------------------
// Property 2 — merge is commutative: merge(a, b) == merge(b, a).
// ----------------------------------------------------------------------------
#[hegel::test]
fn merge_is_commutative(tc: hegel::TestCase) {
    let a = draw_state(&tc);
    let b = draw_state(&tc);
    let ab = merge(&a, &b);
    let ba = merge(&b, &a);
    assert_eq!(ab, ba, "merge is not commutative");
}

// ----------------------------------------------------------------------------
// Property 3 — merge is associative: merge(merge(a, b), c) == merge(a, merge(b, c)).
// ----------------------------------------------------------------------------
#[hegel::test]
fn merge_is_associative(tc: hegel::TestCase) {
    let a = draw_state(&tc);
    let b = draw_state(&tc);
    let c = draw_state(&tc);
    let ab_c = merge(&merge(&a, &b), &c);
    let a_bc = merge(&a, &merge(&b, &c));
    assert_eq!(ab_c, a_bc, "merge is not associative");
}

// ----------------------------------------------------------------------------
// Property 4 — full-sync convergence.
// A single full-sync round (every node merges every other node's pre-sync
// state into itself) drives the cluster to a fixpoint.
// ----------------------------------------------------------------------------
#[hegel::test]
fn full_sync_converges_in_one_round(tc: hegel::TestCase) {
    let n = tc.draw(generators::integers::<usize>().min_value(1).max_value(6));
    let mut nodes: Vec<NodeState> = (0..n).map(|_| draw_state(&tc)).collect();

    let snapshot = nodes.clone();
    for i in 0..n {
        for j in 0..n {
            if i != j {
                nodes[i] = merge(&nodes[i], &snapshot[j]);
            }
        }
    }

    for i in 1..n {
        assert_eq!(
            nodes[0], nodes[i],
            "post-full-sync divergence between node 0 and node {}",
            i
        );
    }
}

// ----------------------------------------------------------------------------
// Property 5 — pairwise gossip converges after a final full-sync round,
// regardless of interleaving of writes and pairwise merges.
// ----------------------------------------------------------------------------
#[hegel::test]
fn interleaved_writes_and_gossip_converge(tc: hegel::TestCase) {
    let n = tc.draw(generators::integers::<usize>().min_value(2).max_value(5));
    let mut nodes: Vec<NodeState> = (0..n).map(|_| NodeState::new()).collect();

    let n_ops = tc.draw(generators::integers::<usize>().min_value(0).max_value(30));
    for _ in 0..n_ops {
        // 0 = write; 1 = pairwise merge
        let op = tc.draw(generators::integers::<u8>().min_value(0).max_value(1));
        if op == 0 {
            let node_idx = tc.draw(
                generators::integers::<usize>()
                    .min_value(0)
                    .max_value(n - 1),
            );
            let k = tc.draw(generators::integers::<Key>().min_value(0).max_value(10));
            let v = tc.draw(generators::integers::<Value>().max_value(1_000));
            let t = tc.draw(generators::integers::<Timestamp>().max_value(1_000));
            nodes[node_idx].write(k, v, t);
        } else {
            let a = tc.draw(
                generators::integers::<usize>()
                    .min_value(0)
                    .max_value(n - 1),
            );
            let b = tc.draw(
                generators::integers::<usize>()
                    .min_value(0)
                    .max_value(n - 1),
            );
            if a != b {
                let merged = merge(&nodes[a], &nodes[b]);
                nodes[a] = merged.clone();
                nodes[b] = merged;
            }
        }
    }

    // Final full-sync round (quiescent mode, no new writes).
    let snapshot = nodes.clone();
    for i in 0..n {
        for j in 0..n {
            if i != j {
                nodes[i] = merge(&nodes[i], &snapshot[j]);
            }
        }
    }

    for i in 1..n {
        assert_eq!(
            nodes[0], nodes[i],
            "final convergence failed between node 0 and node {}",
            i
        );
    }
}

// ----------------------------------------------------------------------------
// Property 6 — LWW semantics: highest timestamp wins across any sequence.
// ----------------------------------------------------------------------------
#[hegel::test]
fn lww_highest_timestamp_wins(tc: hegel::TestCase) {
    let a = draw_state(&tc);
    let b = draw_state(&tc);
    let merged = merge(&a, &b);

    for k in merged.keys() {
        let entry_merged = merged.get(k).expect("key known to exist");
        let in_a = a.get(k);
        let in_b = b.get(k);

        // The merged value must be one of the input values for this key.
        match (in_a, in_b) {
            (Some(ea), Some(eb)) => {
                // Expected winner by LWW + max-value tiebreak.
                let winner = if ea.timestamp != eb.timestamp {
                    if ea.timestamp > eb.timestamp { ea } else { eb }
                } else if ea.value >= eb.value {
                    ea
                } else {
                    eb
                };
                assert_eq!(entry_merged, winner, "LWW pick wrong for key {}", k);
            }
            (Some(e), None) | (None, Some(e)) => {
                assert_eq!(entry_merged, e, "singleton key {} changed", k);
            }
            (None, None) => panic!("merged key {} not in either input", k),
        }
    }
}
