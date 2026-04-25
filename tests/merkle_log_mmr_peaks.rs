//! Property-based tests for MMR peak decomposition on `cosaci::merkle_log`.
//!
//! Closes the last `†` on `hypotheses/merkle-log-append-only.md` — the
//! MMR structural claim. v0.1 computes peaks on demand rather than
//! caching them, but the **peak-stability property** is the load-bearing
//! one: once a peak has formed (the log has grown past `start + 2^h`),
//! that peak's hash is a pure function of `leaves[start..start+2^h]`
//! and never changes as more leaves are appended.

use cosaci::merkle_log::{Hash, MerkleLog, peak_heights};
use hegel::generators;

fn draw_hash(tc: &hegel::TestCase) -> Hash {
    let v: Vec<u8> = tc.draw(generators::binary().min_size(32).max_size(32));
    let mut arr = [0_u8; 32];
    arr.copy_from_slice(&v);
    arr
}

// ----------------------------------------------------------------------------
// Property 1 — peak_heights agrees with binary decomposition.
// ----------------------------------------------------------------------------
#[hegel::test]
fn peak_heights_are_bit_positions(tc: hegel::TestCase) {
    let n = tc.draw(generators::integers::<u64>());
    let heights = peak_heights(n);

    // Number of peaks = popcount(n).
    let popcount: u32 = n.count_ones();
    assert_eq!(
        heights.len() as u32,
        popcount,
        "peak count mismatch for n={}: got {} peaks, expected {}",
        n,
        heights.len(),
        popcount
    );

    // Descending order (MSB first).
    for pair in heights.windows(2) {
        assert!(
            pair[0] > pair[1],
            "peak heights not strictly descending: {:?}",
            heights
        );
    }

    // Each listed height corresponds to a 1-bit in n.
    for &h in &heights {
        assert!(
            (n >> h) & 1 == 1,
            "height {} listed but bit not set in n={}",
            h,
            n
        );
    }

    // Sum of 2^h over peak heights equals n (peaks cover exactly the leaves).
    let covered: u64 = heights.iter().map(|&h| 1_u64 << h).sum();
    assert_eq!(
        covered, n,
        "peaks don't cover n: covered={}, n={}",
        covered, n
    );
}

// ----------------------------------------------------------------------------
// Property 2 — empty log has no peaks.
// ----------------------------------------------------------------------------
#[hegel::test]
fn empty_log_has_no_peaks(_tc: hegel::TestCase) {
    let log = MerkleLog::new();
    assert_eq!(log.peak_hashes(0), Vec::<Hash>::new());
}

// ----------------------------------------------------------------------------
// Property 3 — peak count matches popcount of length.
// ----------------------------------------------------------------------------
#[hegel::test]
fn peak_count_matches_popcount(tc: hegel::TestCase) {
    let n = tc.draw(generators::integers::<u64>().min_value(1).max_value(64));
    let mut log = MerkleLog::new();
    for _ in 0..n {
        log.append(draw_hash(&tc));
    }
    let peaks = log.peak_hashes(n);
    assert_eq!(peaks.len() as u32, n.count_ones());
}

// ----------------------------------------------------------------------------
// Property 4 — peak-stability (the load-bearing MMR claim).
// For any `n_before ≤ n_after`, the peaks that exist in BOTH logs at
// the same leaf-coverage extent must have identical hashes. Concretely:
// the first k peaks of `peak_hashes(n_before)` appear in
// `peak_hashes(n_after)` IF AND ONLY IF their coverage spans (by position
// accumulation) align. Weaker test: when `n_before` is a power of two,
// its single peak covers leaves [0, n_before) — and ANY `n_after` with a
// bit at that height and no lower bits in that prefix shows the same peak.
//
// Simplest testable form: `peak_hashes(2^h)` has one element, the Merkle
// root of the first 2^h leaves, and this equals the `h`-th peak in
// `peak_hashes(any n with the high bit at h and nothing higher)` —
// as long as the coverage accumulates identically (i.e., start = 0).
//
// We use a clean special case: `peak_hashes(2^h)` is stable across all
// log lengths `L` where `L` has the bit set at position `h` and no
// higher bits set. The first peak of `peak_hashes(L)` covers `leaves[0, 2^h)`
// exactly and must equal `peak_hashes(2^h)[0]`.
// ----------------------------------------------------------------------------
#[hegel::test]
fn first_peak_is_stable_across_extensions(tc: hegel::TestCase) {
    // Pick h small enough that 2^h fits comfortably.
    let h = tc.draw(generators::integers::<u32>().min_value(0).max_value(6));
    let first_peak_size = 1_u64 << h;

    // Extra leaves appended after the first peak, bounded so no higher
    // peak forms (extra < first_peak_size).
    let extra = tc.draw(
        generators::integers::<u64>()
            .min_value(0)
            .max_value(first_peak_size - 1),
    );

    let total = first_peak_size + extra;
    let mut log = MerkleLog::new();
    for _ in 0..total {
        log.append(draw_hash(&tc));
    }

    // Peak hashes at exactly 2^h: one peak.
    let peaks_at_power = log.peak_hashes(first_peak_size);
    assert_eq!(peaks_at_power.len(), 1);

    // Peak hashes at total length: multiple peaks. First one must match.
    let peaks_at_total = log.peak_hashes(total);
    assert_eq!(
        peaks_at_total[0], peaks_at_power[0],
        "first peak shifted when log extended from {} to {}",
        first_peak_size, total
    );
}

// ----------------------------------------------------------------------------
// Property 5 — peak_hashes is deterministic in input.
// ----------------------------------------------------------------------------
#[hegel::test]
fn peak_hashes_deterministic(tc: hegel::TestCase) {
    let n = tc.draw(generators::integers::<u64>().min_value(1).max_value(40));
    let mut log = MerkleLog::new();
    for _ in 0..n {
        log.append(draw_hash(&tc));
    }
    let a = log.peak_hashes(n);
    let b = log.peak_hashes(n);
    assert_eq!(a, b);
}

// ----------------------------------------------------------------------------
// Property 6 — single-peak case: when length is a power of 2, peak_hashes
// returns exactly one hash and it equals the Merkle root over those leaves
// (i.e., root_at(length)).
// ----------------------------------------------------------------------------
#[hegel::test]
fn power_of_two_has_single_peak_equal_to_root(tc: hegel::TestCase) {
    let h = tc.draw(generators::integers::<u32>().min_value(0).max_value(6));
    let n = 1_u64 << h;

    let mut log = MerkleLog::new();
    for _ in 0..n {
        log.append(draw_hash(&tc));
    }
    let peaks = log.peak_hashes(n);
    assert_eq!(peaks.len(), 1);
    let root = log.root_at(n).expect("nonempty root");
    assert_eq!(
        peaks[0], root,
        "single peak != root at power-of-2 length {}",
        n
    );
}
