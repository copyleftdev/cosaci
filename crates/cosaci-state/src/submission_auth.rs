//! Submission authentication + rate-limit gate (issue #46).
//!
//! Pure layer between the wire (`JobSubmission` JSON parsed from
//! coord stdin) and the job queue. Three gates apply, in order:
//!
//! 1. **Tenant lookup** — `tenant_id` must be present in the
//!    `crate::tenant::TenantRegistry`. Unknown tenants are rejected
//!    before any signature work.
//! 2. **Signature verification** — the submission carries
//!    `(payload, pubkey, signature)`. The coordinator verifies
//!    `SHA-256(pubkey) == registry[tenant_id].signing_fp`, then
//!    `ed25519::verify(pubkey, canonical_bytes(payload), signature)`.
//!    Mismatches at either step are `BadSignature`.
//! 3. **Rate limiting** — the per-tenant token bucket
//!    (`rate_limit::RateLimiter::accept_with_config` with the
//!    tenant's own capacity + refill) decides admission. A failing
//!    bucket is `RateLimited`.
//!
//! The output of [`verify_and_admit`] is the [`AuthCheck`] verdict
//! the coordinator acts on. The function is pure relative to its
//! injected `RateLimiter`; `RateLimiter` itself is deterministic
//! under a `Clock` trait, so the whole gate is testable under the
//! existing DST harness.

use cosaci_core::clock::Clock;
use cosaci_core::signing::{Signature, VerifyingKey, verify};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::rate_limit::RateLimiter;
use crate::tenant::{TenantId, TenantRegistry, fingerprint};

/// Canonical, signable shape of a job submission. The coordinator
/// signs the CBOR canonical encoding of this struct; an attacker
/// who tampers with any field invalidates the signature.
///
/// Note: the on-the-wire JSON shape that goes through coord stdin
/// is allowed to spell `kind` as a lower-case string (`"add"` /
/// `"mul"`) per the issue-#32 contract; the canonical encoding
/// uses the wire variant unchanged so the JSON parse and the
/// signing path agree byte-for-byte.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobSubmissionPayload {
    /// Tenant id this submission is signed under.
    pub tenant_id: TenantId,
    /// Canned-job kind discriminator (matches the issue-#32 wire
    /// shape). Free-form `String` so future kinds (post-#40 module
    /// references) don't require a wire change.
    pub kind: String,
    /// First i32 argument.
    pub a: i32,
    /// Second i32 argument.
    pub b: i32,
    /// Per-job deadline in seconds.
    pub deadline_secs: u32,
    /// Replay-protection nonce. The coordinator does not yet
    /// enforce uniqueness in v0.3 — that's the bloom-filter follow-
    /// on (`hypotheses/replay-protection.md`'s submission-side
    /// extension); for now a freshly-generated random u128 is the
    /// expected client behavior.
    pub nonce: u128,
}

/// Canonical signable bytes of a [`JobSubmissionPayload`].
///
/// CBOR via `ciborium` because the rest of the wire protocol
/// already canonicalizes through ciborium — keeping one
/// serialization path means an attacker who can produce a JSON
/// re-serialization with different bytes can't slip a different
/// signed payload past the verifier.
///
/// # Errors
///
/// `ciborium` returns errors only for I/O on the writer; this
/// function uses an in-memory `Vec`, so the error path is
/// effectively unreachable for these types. The `Result` is
/// preserved so the caller doesn't have to assume infallibility.
pub fn canonical_bytes(payload: &JobSubmissionPayload) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    ciborium::into_writer(payload, &mut buf)
        .map_err(|e| format!("ciborium encode JobSubmissionPayload: {e}"))?;
    Ok(buf)
}

/// Outcome of running the auth gate on one submission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthCheck {
    /// Signature valid + rate-limit token consumed. Coordinator
    /// proceeds to enqueue the job.
    Ok,
    /// `tenant_id` not found in the registry.
    UnknownTenant,
    /// Pubkey fingerprint didn't match the registry, or ed25519
    /// signature verification failed against the canonical bytes.
    /// The two error modes share a verdict on purpose — leaking
    /// "wrong pubkey" vs. "bad signature" gives an attacker an
    /// oracle for which tenant ids are registered.
    BadSignature,
    /// Tenant's rate bucket is empty.
    RateLimited,
}

/// Apply the three-stage gate to one submission. The
/// [`RateLimiter`] is consumed only on `Ok` — `BadSignature` and
/// `UnknownTenant` short-circuit before any token spend, so an
/// attacker can't drain a tenant's bucket with forged signatures.
pub fn verify_and_admit<C: Clock>(
    payload: &JobSubmissionPayload,
    pubkey: &[u8; 32],
    signature: &[u8; 64],
    registry: &TenantRegistry,
    rate_limiter: &mut RateLimiter<C>,
) -> AuthCheck {
    let Some(tenant) = registry.get(payload.tenant_id) else {
        return AuthCheck::UnknownTenant;
    };

    // Stage 2a: pubkey fingerprint matches the registry.
    if fingerprint(pubkey) != tenant.signing_fp {
        return AuthCheck::BadSignature;
    }

    // Stage 2b: signature verifies against canonical payload bytes.
    let Ok(bytes) = canonical_bytes(payload) else {
        return AuthCheck::BadSignature;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(pubkey) else {
        return AuthCheck::BadSignature;
    };
    let sig = Signature::from_bytes(signature);
    if verify(&verifying_key, &bytes, &sig).is_err() {
        return AuthCheck::BadSignature;
    }

    // Stage 3: rate limit. Consume one token per submission.
    if !rate_limiter.accept_with_config(
        payload.tenant_id,
        1,
        tenant.rate_capacity,
        tenant.rate_refill_per_sec,
    ) {
        return AuthCheck::RateLimited;
    }

    AuthCheck::Ok
}

/// SHA-256 of a tenant's pubkey — same primitive as
/// `crate::tenant::fingerprint`, re-exposed under a more
/// discoverable name in this module's API surface.
#[must_use]
pub fn pubkey_fingerprint(pubkey: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(pubkey);
    h.finalize().into()
}
