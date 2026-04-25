//! Agent enrollment registry.
//!
//! Source: `SPEC.md` §5.1 / `hypotheses/enrollment-gate-enforcement.md`
//! (issue #45, class A). The coordinator gates `Register` on a
//! pre-provisioned set of `(runner_id, signing_fp, vrf_fp)` triples;
//! agents whose fingerprints aren't in the set are rejected after
//! mTLS + VRF-of-possession but before they enter the committee pool.
//!
//! # File format (v0.3 MVP)
//!
//! One enrollment per non-empty, non-comment line. Fields are
//! whitespace-separated:
//!
//! ```text
//! <runner_id> <signing_fp_hex> <vrf_fp_hex> <enrolled_at_unix_ns> <initial_reputation>
//! ```
//!
//! - `runner_id`: u64
//! - `signing_fp_hex`: 64 lowercase hex chars (SHA-256 of the
//!   ed25519 verifying-key bytes)
//! - `vrf_fp_hex`: 64 lowercase hex chars (SHA-256 of the schnorrkel
//!   sr25519 VRF public-key bytes)
//! - `enrolled_at_unix_ns`: i64 unix nanoseconds (admin-issuance time)
//! - `initial_reputation`: f32 in `[0.0, 1.0]` — seed for
//!   `cosaci-core::reputation` once that ledger lands
//!
//! Lines starting with `#` are comments. Empty lines are ignored. The
//! parser is strict about field count + numeric format; malformed
//! lines fail the whole load with `InvalidData`.
//!
//! v0.4 will replace this with a TOML or sqlite-backed format and a
//! proper `cosaci-admin` CLI for enroll / revoke (issue #53).

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use sha2::{Digest, Sha256};

/// One enrollment record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnrolledRecord {
    /// Runner identifier this enrollment is for.
    pub runner_id: u64,
    /// SHA-256 of the runner's ed25519 verifying-key bytes.
    pub signing_fp: [u8; 32],
    /// SHA-256 of the runner's schnorrkel sr25519 VRF public-key bytes.
    pub vrf_fp: [u8; 32],
    /// When the admin issued this enrollment (unix nanoseconds).
    pub enrolled_at_unix_ns: i64,
    /// Reputation seed at enrollment time. `f32` (rather than `f64`) to
    /// match the typical reputation-ledger precision; ignored by the
    /// gate itself, consumed by downstream reputation accounting.
    pub initial_reputation_milli: u16,
}

impl EnrolledRecord {
    /// Reputation as `f32` in `[0.0, 1.0]`. Stored internally as a u16
    /// in milli-units (`0..=1000`) so the type stays trivially `Eq`.
    #[must_use]
    pub fn initial_reputation(&self) -> f32 {
        f32::from(self.initial_reputation_milli) / 1000.0
    }
}

/// In-memory enrollment registry. Keyed by `runner_id`; lookups
/// verify both fingerprints match what the file said.
#[derive(Clone, Debug, Default)]
pub struct EnrollmentSet {
    records: HashMap<u64, EnrolledRecord>,
}

impl EnrollmentSet {
    /// Empty registry. With this set, every `is_enrolled` query
    /// returns `false`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a record, returning the previous value for the same
    /// `runner_id` if any. Used by tests and the SIGHUP reload path.
    pub fn insert(&mut self, record: EnrolledRecord) -> Option<EnrolledRecord> {
        self.records.insert(record.runner_id, record)
    }

    /// Number of enrollments.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the registry holds zero enrollments.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Look up a record by `runner_id`. Returns `None` if absent.
    #[must_use]
    pub fn get(&self, runner_id: u64) -> Option<&EnrolledRecord> {
        self.records.get(&runner_id)
    }

    /// Iterate every enrolled record. Iteration order is unspecified
    /// (HashMap-backed); callers that need deterministic order
    /// should sort by `runner_id`.
    pub fn iter(&self) -> impl Iterator<Item = &EnrolledRecord> {
        self.records.values()
    }

    /// True iff `runner_id` is enrolled AND the supplied fingerprints
    /// match the enrolled values exactly. A matching `runner_id` with
    /// any divergent fingerprint returns `false` — this catches
    /// impersonation attempts where an attacker claims an enrolled
    /// id with their own keys.
    #[must_use]
    pub fn is_enrolled(&self, runner_id: u64, signing_fp: &[u8; 32], vrf_fp: &[u8; 32]) -> bool {
        match self.records.get(&runner_id) {
            Some(r) => &r.signing_fp == signing_fp && &r.vrf_fp == vrf_fp,
            None => false,
        }
    }

    /// Load enrollments from a file at `path`. The file format is
    /// documented at module level. Empty `path` content yields an
    /// empty set (not an error).
    ///
    /// # Errors
    ///
    /// I/O errors from reading the file, or `InvalidData` on a
    /// malformed line (wrong field count, bad hex, bad numeric).
    pub fn load_from_path<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let text = fs::read_to_string(path)?;
        Self::parse(&text)
    }

    /// Parse the on-wire format from a string. Same semantics as
    /// [`load_from_path`](Self::load_from_path).
    ///
    /// # Errors
    ///
    /// `InvalidData` for malformed records.
    pub fn parse(text: &str) -> std::io::Result<Self> {
        let mut set = Self::new();
        for (lineno, line) in text.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let record = parse_line(trimmed).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("enrollment line {}: {}", lineno + 1, e),
                )
            })?;
            set.insert(record);
        }
        Ok(set)
    }
}

fn parse_line(line: &str) -> Result<EnrolledRecord, String> {
    let mut iter = line.split_whitespace();
    let runner_id: u64 = next_field(&mut iter, "runner_id")?
        .parse()
        .map_err(|e| format!("runner_id: {e}"))?;
    let signing_fp_hex = next_field(&mut iter, "signing_fp")?;
    let vrf_fp_hex = next_field(&mut iter, "vrf_fp")?;
    let enrolled_at_unix_ns: i64 = next_field(&mut iter, "enrolled_at_unix_ns")?
        .parse()
        .map_err(|e| format!("enrolled_at_unix_ns: {e}"))?;
    let reputation_field = next_field(&mut iter, "initial_reputation")?;
    let reputation: f32 = reputation_field
        .parse()
        .map_err(|e| format!("initial_reputation: {e}"))?;
    if iter.next().is_some() {
        return Err("trailing fields after initial_reputation".to_string());
    }
    if !(0.0..=1.0).contains(&reputation) {
        return Err(format!("initial_reputation {reputation} not in [0.0, 1.0]"));
    }
    let signing_fp = parse_hex32(signing_fp_hex).map_err(|e| format!("signing_fp: {e}"))?;
    let vrf_fp = parse_hex32(vrf_fp_hex).map_err(|e| format!("vrf_fp: {e}"))?;
    Ok(EnrolledRecord {
        runner_id,
        signing_fp,
        vrf_fp,
        enrolled_at_unix_ns,
        initial_reputation_milli: (reputation * 1000.0).round() as u16,
    })
}

fn next_field<'a, I: Iterator<Item = &'a str>>(
    iter: &mut I,
    name: &str,
) -> Result<&'a str, String> {
    iter.next().ok_or_else(|| format!("missing field {name}"))
}

fn parse_hex32(s: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", s.len()));
    }
    let mut out = [0_u8; 32];
    for (i, byte_out) in out.iter_mut().enumerate() {
        let hi = hex_digit(s.as_bytes()[i * 2])?;
        let lo = hex_digit(s.as_bytes()[i * 2 + 1])?;
        *byte_out = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_digit(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        other => Err(format!("non-hex byte 0x{other:02x}")),
    }
}

/// Compute the SHA-256 fingerprint of a 32-byte public key.
#[must_use]
pub fn fingerprint(pubkey: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(pubkey);
    h.finalize().into()
}

/// Render a 32-byte fingerprint as 64 lowercase hex chars. Inverse of
/// `parse_hex32`.
#[must_use]
pub fn fingerprint_hex(fp: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for &b in fp {
        s.push(hex_nibble(b >> 4));
        s.push(hex_nibble(b & 0x0f));
    }
    s
}

fn hex_nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + n - 10) as char,
        _ => unreachable!(),
    }
}
