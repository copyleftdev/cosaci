//! Tenant registry (issue #46) — tenant identity + per-tenant rate
//! quota persisted alongside the agent enrollment file.
//!
//! A *tenant* is an external identity authorized to submit jobs to the
//! coordinator. Each tenant carries:
//!
//! - A `tenant_id` (u64, operator-chosen).
//! - An ed25519 `signing_pubkey` — submissions are signed under this
//!   key and the coordinator rejects any submission whose signature
//!   doesn't verify.
//! - A token-bucket rate quota: `(rate_capacity, rate_refill_per_sec)`.
//!   The coordinator wires this through
//!   `cosaci-state::rate_limit::RateLimiter::accept_with_config` so
//!   each tenant's bucket is sized independently.
//!
//! The wire format mirrors `enrollment.txt` (one record per line,
//! whitespace-separated, `#`-prefixed comments) so an operator
//! managing both files learns one syntax.
//!
//! ```text
//! # tenant_id  signing_fp_hex                                                    capacity refill_per_sec  registered_at_unix_ns
//! 1           abcd…                                                              100      10              1700000000000000000
//! 2           ef01…                                                              50       5               1700000001000000000
//! ```
//!
//! Note: the file stores the *fingerprint* of the signing pubkey
//! (SHA-256), not the raw 32-byte pubkey. The submission envelope
//! carries the raw pubkey alongside the signature; the coordinator
//! checks `SHA-256(pubkey) == registry[tenant_id].signing_fp` and
//! then verifies the signature against `pubkey`. Fingerprint storage
//! mirrors `enrollment.txt` and keeps the operator-facing file
//! grep-friendly.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;

use sha2::{Digest, Sha256};

/// Tenant identity used as the rate-limit key.
pub type TenantId = u64;

/// SHA-256 of a tenant's ed25519 signing pubkey. 32 bytes.
pub type SigningFingerprint = [u8; 32];

/// One tenant record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenantRecord {
    /// Operator-chosen tenant id.
    pub tenant_id: TenantId,
    /// SHA-256 of the tenant's ed25519 signing pubkey.
    pub signing_fp: SigningFingerprint,
    /// Token-bucket capacity (peak burst, in tokens — typically jobs).
    pub rate_capacity: u64,
    /// Refill rate in tokens per second.
    pub rate_refill_per_sec: u64,
    /// Wall-clock time the tenant was registered, nanoseconds since
    /// the Unix epoch. Operator-supplied; not interpreted by the
    /// coord beyond informational logging.
    pub registered_at_unix_ns: u64,
}

/// In-memory tenant registry, keyed by `tenant_id`. Loaded from a
/// flat file at coord startup; not mutated at runtime in v0.3
/// (operator restarts coord to pick up changes).
#[derive(Clone, Debug, Default)]
pub struct TenantRegistry {
    by_id: HashMap<TenantId, TenantRecord>,
}

impl TenantRegistry {
    /// Empty registry — no tenant authorized.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of registered tenants.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// True if no tenants are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// Insert a record. Returns `Err` if a record with the same
    /// `tenant_id` already exists (operator must `revoke` first).
    ///
    /// # Errors
    ///
    /// Returns `io::ErrorKind::AlreadyExists` if the `tenant_id` is
    /// already present.
    pub fn insert(&mut self, record: TenantRecord) -> io::Result<()> {
        if self.by_id.contains_key(&record.tenant_id) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("tenant_id {} already registered", record.tenant_id),
            ));
        }
        self.by_id.insert(record.tenant_id, record);
        Ok(())
    }

    /// Look up a record by `tenant_id`.
    #[must_use]
    pub fn get(&self, tenant_id: TenantId) -> Option<&TenantRecord> {
        self.by_id.get(&tenant_id)
    }

    /// Iterate the registry in `tenant_id` order. Used by the admin
    /// CLI for deterministic output and by RUNBOOK examples.
    pub fn iter(&self) -> impl Iterator<Item = &TenantRecord> {
        let mut sorted: Vec<&TenantRecord> = self.by_id.values().collect();
        sorted.sort_by_key(|r| r.tenant_id);
        sorted.into_iter()
    }

    /// Load a registry from the wire file format. Comments
    /// (`#`-prefixed lines) and blank lines are skipped; malformed
    /// lines return `io::ErrorKind::InvalidData` with the line
    /// number and a short description.
    ///
    /// # Errors
    ///
    /// Returns `io::Error` for any I/O failure or any malformed
    /// record. The first malformed line aborts loading — the
    /// operator's intent on the rest of the file is ambiguous.
    pub fn load_from_path(path: impl AsRef<Path>) -> io::Result<Self> {
        let bytes = fs::read_to_string(path.as_ref())?;
        let mut reg = Self::new();
        for (lineno, line) in bytes.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let record = parse_line(lineno + 1, trimmed)?;
            reg.insert(record)?;
        }
        Ok(reg)
    }
}

/// SHA-256 fingerprint of an ed25519 signing pubkey. Convenience
/// wrapper to keep the call site terse.
#[must_use]
pub fn fingerprint(pubkey: &[u8; 32]) -> SigningFingerprint {
    let mut h = Sha256::new();
    h.update(pubkey);
    h.finalize().into()
}

/// Lowercase-hex encoding of a fingerprint. Used for the on-disk
/// file format and for log lines.
#[must_use]
pub fn fingerprint_hex(fp: &SigningFingerprint) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(64);
    for b in fp {
        write!(&mut s, "{b:02x}").expect("write to String");
    }
    s
}

fn parse_line(lineno: usize, line: &str) -> io::Result<TenantRecord> {
    let mut it = line.split_ascii_whitespace();
    let tenant_id_s = next_field(&mut it, lineno, "tenant_id")?;
    let signing_fp_s = next_field(&mut it, lineno, "signing_fp_hex")?;
    let cap_s = next_field(&mut it, lineno, "rate_capacity")?;
    let refill_s = next_field(&mut it, lineno, "rate_refill_per_sec")?;
    let registered_s = next_field(&mut it, lineno, "registered_at_unix_ns")?;
    if it.next().is_some() {
        return Err(invalid(
            lineno,
            "trailing fields after registered_at_unix_ns",
        ));
    }
    let tenant_id: TenantId = tenant_id_s
        .parse()
        .map_err(|_| invalid(lineno, "tenant_id not a u64"))?;
    let signing_fp = parse_hex32(signing_fp_s)
        .ok_or_else(|| invalid(lineno, "signing_fp_hex not 64 lowercase-hex chars"))?;
    let rate_capacity: u64 = cap_s
        .parse()
        .map_err(|_| invalid(lineno, "rate_capacity not a u64"))?;
    let rate_refill_per_sec: u64 = refill_s
        .parse()
        .map_err(|_| invalid(lineno, "rate_refill_per_sec not a u64"))?;
    let registered_at_unix_ns: u64 = registered_s
        .parse()
        .map_err(|_| invalid(lineno, "registered_at_unix_ns not a u64"))?;

    Ok(TenantRecord {
        tenant_id,
        signing_fp,
        rate_capacity,
        rate_refill_per_sec,
        registered_at_unix_ns,
    })
}

fn next_field<'a, I: Iterator<Item = &'a str>>(
    it: &mut I,
    lineno: usize,
    name: &str,
) -> io::Result<&'a str> {
    it.next()
        .ok_or_else(|| invalid(lineno, &format!("missing field: {name}")))
}

fn invalid(lineno: usize, msg: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("tenants.txt line {lineno}: {msg}"),
    )
}

/// Parse 64 lowercase-hex chars into a `[u8; 32]`. Returns `None`
/// for any non-hex character or wrong length.
#[must_use]
pub fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0_u8; 32];
    for (i, byte_pair) in s.as_bytes().chunks_exact(2).enumerate() {
        let hi = hex_nibble(byte_pair[0])?;
        let lo = hex_nibble(byte_pair[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}
