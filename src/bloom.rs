//! Probabilistic-membership filter — a minimal Bloom filter.
//!
//! Source: primitive for the `hypotheses/replay-protection.md` scale
//! sub-claim (bloom-backed nonce window at 10⁶-nonce workloads). v0.1
//! `ReplayGuard` still uses an exact `HashMap` index; this module
//! provides the bloom primitive and its falsifiable false-positive-rate
//! bound, so the sub-claim has test coverage even before the
//! `ReplayGuard` refactor.
//!
//! Bloom construction: `m` bits, `k` hash functions derived from
//! SHA-256. No false negatives; false positive rate after `n` distinct
//! inserts is bounded by `(1 − exp(−kn/m))^k`.

use sha2::{Digest, Sha256};

/// Minimal Bloom filter. `m` bits (stored as packed `u64` words),
/// `k` SHA-256-derived hash functions.
#[derive(Clone, Debug)]
pub struct BloomFilter {
    bits: Vec<u64>,
    m: usize,
    k: usize,
}

impl BloomFilter {
    /// Construct an empty filter of `m_bits` bits with `k_hashes` hash
    /// functions.
    ///
    /// # Panics
    ///
    /// Panics if `m_bits == 0` or `k_hashes == 0`.
    #[must_use]
    pub fn new(m_bits: usize, k_hashes: usize) -> Self {
        assert!(m_bits > 0, "m_bits must be > 0");
        assert!(k_hashes > 0, "k_hashes must be > 0");
        let n_words = m_bits.div_ceil(64);
        Self {
            bits: vec![0; n_words],
            m: m_bits,
            k: k_hashes,
        }
    }

    fn hash_indices(&self, item: &[u8]) -> Vec<usize> {
        let mut idxs = Vec::with_capacity(self.k);
        for i in 0..self.k {
            let mut h = Sha256::new();
            h.update(item);
            h.update(&(i as u32).to_le_bytes());
            let digest: [u8; 32] = h.finalize().into();
            let mut eight = [0_u8; 8];
            eight.copy_from_slice(&digest[..8]);
            let word = u64::from_le_bytes(eight);
            idxs.push((word as usize) % self.m);
        }
        idxs
    }

    /// Insert an item.
    pub fn insert(&mut self, item: &[u8]) {
        for idx in self.hash_indices(item) {
            let word = idx / 64;
            let bit = idx % 64;
            self.bits[word] |= 1_u64 << bit;
        }
    }

    /// Query an item. Returns `true` if the item *might* be in the set
    /// (definitively true for inserted items; may be a false positive
    /// for non-inserted items). Never returns `false` for an item that
    /// was inserted — no false negatives.
    #[must_use]
    pub fn contains(&self, item: &[u8]) -> bool {
        for idx in self.hash_indices(item) {
            let word = idx / 64;
            let bit = idx % 64;
            if self.bits[word] & (1_u64 << bit) == 0 {
                return false;
            }
        }
        true
    }

    #[must_use]
    pub fn capacity_bits(&self) -> usize {
        self.m
    }

    #[must_use]
    pub fn num_hashes(&self) -> usize {
        self.k
    }
}

/// Theoretical false-positive rate after `n_inserts` distinct insertions
/// in a filter with `m_bits` bits and `k_hashes` hash functions. Standard
/// Bloom-filter formula: `(1 − exp(−kn/m))^k`.
#[must_use]
pub fn theoretical_fp_rate(m_bits: usize, k_hashes: usize, n_inserts: usize) -> f64 {
    let exponent = -(k_hashes as f64) * (n_inserts as f64) / (m_bits as f64);
    let bit_set_prob = 1.0 - exponent.exp();
    bit_set_prob.powi(k_hashes as i32)
}
