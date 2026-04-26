//! SCM webhook signature verification (issue #52).
//!
//! GitHub signs the *raw request body* with HMAC-SHA-256 and
//! delivers the hex digest in the `X-Hub-Signature-256` header
//! prefixed with `sha256=`. GitLab takes a different approach:
//! it sends the shared secret token in plaintext via the
//! `X-Gitlab-Token` header and the receiver compares it
//! constant-time against the configured value.
//!
//! Both functions return [`SignatureError`] for any failure
//! mode and `Ok(())` only when the verification succeeds.
//! Constant-time comparison via `hmac::Mac::verify_slice` (or
//! `subtle`-equivalent) is mandatory — variable-time string
//! equality leaks the secret to a timing attacker.
//!
//! Freshness window: [`is_fresh`] rejects events whose
//! timestamp is more than `window_secs` away from `now`. The
//! window matters even when the signature is valid: a
//! man-in-the-middle who captured a signed webhook can replay
//! it later if the receiver doesn't enforce freshness.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

/// HTTP header GitHub uses to deliver the HMAC-SHA-256
/// signature of the request body. The value is `sha256=` +
/// 64 lowercase hex chars.
pub const GITHUB_SIGNATURE_HEADER: &str = "X-Hub-Signature-256";

/// HTTP header GitLab uses to deliver the shared secret
/// token. The value is the secret itself in plaintext —
/// receivers compare constant-time against the configured
/// value.
pub const GITLAB_TOKEN_HEADER: &str = "X-Gitlab-Token";

/// Errors returned by [`verify_github_signature`] /
/// [`verify_gitlab_token`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureError {
    /// Signature header was absent or had a value the
    /// validator can't make sense of (wrong prefix, wrong
    /// length, non-hex characters, or — in the GitLab path —
    /// an empty token).
    Malformed,
    /// Signature/token format was OK but the verification
    /// failed under a constant-time comparison.
    BadSignature,
    /// The event's timestamp is outside the configured
    /// freshness window (replay-protection).
    Stale,
}

impl std::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed => write!(f, "malformed signature header"),
            Self::BadSignature => write!(f, "bad signature"),
            Self::Stale => write!(f, "stale event (outside freshness window)"),
        }
    }
}

impl std::error::Error for SignatureError {}

/// Verify a GitHub webhook signature.
///
/// `body` is the raw request body (bytes — **don't**
/// deserialize and re-serialize the JSON, the round-trip
/// usually changes whitespace and breaks HMAC). `header_value`
/// is the value of the `X-Hub-Signature-256` header (e.g.
/// `sha256=abcd…`). `secret` is the shared HMAC key configured
/// at webhook setup time.
///
/// # Errors
///
/// Returns `SignatureError::Malformed` if the header is
/// missing the `sha256=` prefix, has wrong length, or contains
/// non-hex chars. Returns `SignatureError::BadSignature` if
/// the HMAC doesn't match.
pub fn verify_github_signature(
    body: &[u8],
    header_value: &str,
    secret: &[u8],
) -> Result<(), SignatureError> {
    let hex = header_value
        .strip_prefix("sha256=")
        .ok_or(SignatureError::Malformed)?;
    let provided = parse_hex32(hex).ok_or(SignatureError::Malformed)?;

    let mut mac = <Hmac<Sha256>>::new_from_slice(secret).map_err(|_| SignatureError::Malformed)?;
    mac.update(body);
    mac.verify_slice(&provided)
        .map_err(|_| SignatureError::BadSignature)
}

/// Verify a GitLab webhook token.
///
/// GitLab doesn't HMAC the body — it just expects the receiver
/// to compare the value of the `X-Gitlab-Token` header
/// constant-time against the configured shared secret. (This
/// is weaker than GitHub's scheme: an attacker who learns the
/// token can forge any payload. Operators should pair this
/// with a network-level filter — only accept connections from
/// GitLab's IP ranges over TLS.)
///
/// # Errors
///
/// Returns `SignatureError::Malformed` if `header_value` is
/// empty or `expected_token` is empty (a misconfigured deploy
/// must not silently accept everything). Returns
/// `SignatureError::BadSignature` if the strings disagree.
pub fn verify_gitlab_token(header_value: &str, expected_token: &str) -> Result<(), SignatureError> {
    if header_value.is_empty() || expected_token.is_empty() {
        return Err(SignatureError::Malformed);
    }
    if constant_time_eq(header_value.as_bytes(), expected_token.as_bytes()) {
        Ok(())
    } else {
        Err(SignatureError::BadSignature)
    }
}

/// Reject events whose timestamp is more than `window_secs`
/// away from `now_unix_secs` in either direction. The window
/// matters even when the signature is valid: a captured-and-
/// replayed webhook stays bit-equal forever, and only the
/// freshness check rejects it.
///
/// `event_unix_secs == now_unix_secs` is fresh.
/// `|event - now| <= window_secs` is fresh.
/// Anything else is `Stale`.
#[must_use]
pub fn is_fresh(event_unix_secs: u64, now_unix_secs: u64, window_secs: u64) -> bool {
    event_unix_secs.abs_diff(now_unix_secs) <= window_secs
}

/// Constant-time byte-slice equality. Returns `false` for
/// length-mismatched inputs. We don't pull `subtle` for this
/// since the implementation is two lines and avoiding the
/// extra dep simplifies the audit trail.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
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
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
