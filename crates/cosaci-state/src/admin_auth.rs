//! Admin-session auth gate (issue #53 follow-on).
//!
//! The admin wire protocol (`Envelope::AdminHello` etc.) is the
//! remote-management surface for operators who don't have shell
//! access on the coord host. It sits *behind* mTLS — only clients
//! whose certs are signed by the coord's CA can even reach the
//! handshake — and *also* requires an ed25519 signature from a
//! pubkey on the operator-managed allowlist. The mTLS cert is
//! transport identity; the ed25519 key is action identity.
//!
//! The allowlist file mirrors the shape of `enrollment.txt` and
//! `tenants.txt`:
//!
//! ```text
//! # admin_keys.txt — one record per line, whitespace-separated.
//! #   admin_id    signing_fp_hex                                                    enrolled_at_unix_ns
//! 1             abcd…                                                              1700000000000000000
//! 2             ef01…                                                              1700000001000000000
//! ```
//!
//! `admin_id` is operator-chosen and recorded in audit logs;
//! `signing_fp_hex` is the SHA-256 of the ed25519 signing pubkey
//! the admin client carries on `AdminHello`. The fingerprint
//! storage matches the rest of the family (one syntax for all
//! three files).

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;

use cosaci_core::clock::Clock;
use cosaci_core::signing::{Signature, VerifyingKey, verify};
use sha2::{Digest, Sha256};

/// SHA-256 of an admin's ed25519 signing pubkey. 32 bytes.
pub type AdminSigningFingerprint = [u8; 32];

/// One record in the admin allowlist.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminRecord {
    /// Operator-chosen admin id; recorded with each accepted
    /// hello in the coord's audit log.
    pub admin_id: u64,
    /// SHA-256 fingerprint of the admin's ed25519 signing pubkey.
    pub signing_fp: AdminSigningFingerprint,
    /// Unix-ns timestamp at enrollment.
    pub enrolled_at_unix_ns: u64,
}

/// In-memory admin allowlist, keyed by the signing fingerprint
/// (the value in the `AdminHello`-equivalent envelope is the
/// raw pubkey; we hash + look up).
#[derive(Clone, Debug, Default)]
pub struct AdminKeySet {
    by_fp: HashMap<AdminSigningFingerprint, AdminRecord>,
}

impl AdminKeySet {
    /// Empty set — no admin authorized.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_fp.len()
    }

    /// True if the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_fp.is_empty()
    }

    /// Look up an admin by the SHA-256 fingerprint of their
    /// signing pubkey.
    #[must_use]
    pub fn get(&self, fp: &AdminSigningFingerprint) -> Option<&AdminRecord> {
        self.by_fp.get(fp)
    }

    /// Insert a record. Returns `Err` if a record with the same
    /// `signing_fp` is already present.
    ///
    /// # Errors
    ///
    /// Returns `io::ErrorKind::AlreadyExists` on duplicate
    /// fingerprint.
    pub fn insert(&mut self, record: AdminRecord) -> io::Result<()> {
        if self.by_fp.contains_key(&record.signing_fp) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "admin signing_fp {:02x?}… already enrolled",
                    &record.signing_fp[..4]
                ),
            ));
        }
        self.by_fp.insert(record.signing_fp, record);
        Ok(())
    }

    /// Iterate the set, sorted by `admin_id` (deterministic).
    pub fn iter(&self) -> impl Iterator<Item = &AdminRecord> {
        let mut sorted: Vec<&AdminRecord> = self.by_fp.values().collect();
        sorted.sort_by_key(|r| r.admin_id);
        sorted.into_iter()
    }

    /// Load the allowlist from the on-disk format. Comments
    /// (`#`-prefixed lines) and blank lines are skipped; the first
    /// malformed line aborts loading with `InvalidData`.
    ///
    /// # Errors
    ///
    /// Returns `io::Error` for any I/O failure or any malformed
    /// record.
    pub fn load_from_path(path: impl AsRef<Path>) -> io::Result<Self> {
        let text = fs::read_to_string(path.as_ref())?;
        let mut set = Self::new();
        for (lineno, line) in text.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let record = parse_line(lineno + 1, trimmed)?;
            set.insert(record)?;
        }
        Ok(set)
    }
}

/// Outcome of [`verify_admin_hello`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdminAuthCheck {
    /// Admin authorized — coord may proceed to honor admin requests
    /// on this connection.
    Ok {
        /// `admin_id` from the matched allowlist record. The coord
        /// records this in its audit log alongside whatever
        /// operation runs next.
        admin_id: u64,
    },
    /// Admin pubkey not in the allowlist, OR signature verify
    /// failed, OR `ts_unix_ns` is outside the freshness window.
    /// Verdicts are merged on purpose — the admin protocol
    /// shouldn't leak which keys are configured by responding
    /// differently to "unknown key" vs "bad sig".
    Unauthorized,
}

/// Verify an admin hello message under a clock + allowlist.
///
/// `pubkey` and `signature` are the values from
/// `Envelope::AdminHello`; `ts_unix_ns` is the timestamp from the
/// same envelope; `challenge` is the fixed prefix
/// `ADMIN_HELLO_CHALLENGE` from the protocol.
///
/// `freshness_ns` bounds how far `ts_unix_ns` may be from
/// `clock.now_ns()` in either direction. v0.3 default in the
/// protocol crate is 60s.
pub fn verify_admin_hello<C: Clock>(
    set: &AdminKeySet,
    pubkey: &[u8; 32],
    ts_unix_ns: u64,
    signature: &[u8; 64],
    challenge: &[u8],
    freshness_ns: u64,
    clock: &C,
) -> AdminAuthCheck {
    let now = clock.now_ns();
    let diff = now.abs_diff(ts_unix_ns);
    if diff > freshness_ns {
        return AdminAuthCheck::Unauthorized;
    }

    let fp = {
        let mut h = Sha256::new();
        h.update(pubkey);
        h.finalize().into()
    };
    let Some(record) = set.get(&fp) else {
        return AdminAuthCheck::Unauthorized;
    };

    let Ok(verifying_key) = VerifyingKey::from_bytes(pubkey) else {
        return AdminAuthCheck::Unauthorized;
    };
    let mut signed_bytes = Vec::with_capacity(challenge.len() + 8);
    signed_bytes.extend_from_slice(challenge);
    signed_bytes.extend_from_slice(&ts_unix_ns.to_le_bytes());

    let sig = Signature::from_bytes(signature);
    if verify(&verifying_key, &signed_bytes, &sig).is_err() {
        return AdminAuthCheck::Unauthorized;
    }

    AdminAuthCheck::Ok {
        admin_id: record.admin_id,
    }
}

/// SHA-256 fingerprint helper, mirroring
/// `cosaci-state::enrollment::fingerprint`. Re-exposed here so
/// admin CLI callers can compute fingerprints without pulling
/// `enrollment` into their use-tree.
#[must_use]
pub fn fingerprint(pubkey: &[u8; 32]) -> AdminSigningFingerprint {
    let mut h = Sha256::new();
    h.update(pubkey);
    h.finalize().into()
}

/// Lowercase-hex render of a fingerprint (mirrors
/// `cosaci-state::enrollment::fingerprint_hex`).
#[must_use]
pub fn fingerprint_hex(fp: &AdminSigningFingerprint) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(64);
    for b in fp {
        write!(&mut s, "{b:02x}").expect("write to String");
    }
    s
}

fn parse_line(lineno: usize, line: &str) -> io::Result<AdminRecord> {
    let mut it = line.split_ascii_whitespace();
    let admin_id_s = next_field(&mut it, lineno, "admin_id")?;
    let signing_fp_s = next_field(&mut it, lineno, "signing_fp_hex")?;
    let registered_s = next_field(&mut it, lineno, "enrolled_at_unix_ns")?;
    if it.next().is_some() {
        return Err(invalid(lineno, "trailing fields after enrolled_at_unix_ns"));
    }
    let admin_id: u64 = admin_id_s
        .parse()
        .map_err(|_| invalid(lineno, "admin_id not a u64"))?;
    let signing_fp = parse_hex32(signing_fp_s)
        .ok_or_else(|| invalid(lineno, "signing_fp_hex not 64 lowercase-hex chars"))?;
    let enrolled_at_unix_ns: u64 = registered_s
        .parse()
        .map_err(|_| invalid(lineno, "enrolled_at_unix_ns not a u64"))?;
    Ok(AdminRecord {
        admin_id,
        signing_fp,
        enrolled_at_unix_ns,
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
        format!("admin_keys.txt line {lineno}: {msg}"),
    )
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
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
