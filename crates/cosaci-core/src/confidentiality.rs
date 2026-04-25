//! Envelope encryption.
//!
//! Source: new (public-scale infra); `hypotheses/confidentiality-algebra.md`
//! (class A). v0.1 primitive: ChaCha20-Poly1305 AEAD with 256-bit keys and
//! 96-bit nonces (`chacha20poly1305::ChaCha20Poly1305`). Same crypto
//! primitive is used for both payload encryption (DEK) and DEK wrapping
//! (KEK) — the distinction is only in what plaintext is passed.
//!
//! This module does **not** defend against a malicious *assigned* runner
//! (they legitimately hold the DEK). Confidentiality from runners requires
//! a TEE; see `hypotheses/tee-attestation.md` (class C).

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key as AeadKey, Nonce as AeadNonce};

/// 256-bit symmetric key. Used for both DEK and KEK — the distinction is
/// only in role, not in shape.
pub type SymKey = [u8; 32];

/// 96-bit nonce. Must be unique per (key, message) pair for semantic
/// security; reuse under the same key breaks confidentiality.
pub type Nonce = [u8; 12];

/// Failure modes for `encrypt` / `decrypt` / `wrap_dek` / `unwrap_dek`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AeadError {
    /// Encryption or decryption failed. For decryption this includes:
    /// tampered ciphertext, wrong key, wrong nonce, truncated input.
    Failed,
    /// Unwrap produced bytes of the wrong length to be a `SymKey`.
    BadKeyLength,
}

/// Encrypt `plaintext` under `key` with `nonce`. Returns ciphertext
/// including the Poly1305 tag.
///
/// # Errors
///
/// Returns `AeadError::Failed` if the underlying AEAD implementation
/// rejects the input (in practice: never for valid `(key, nonce)` — only
/// if input sizes are pathological).
pub fn encrypt(key: &SymKey, nonce: &Nonce, plaintext: &[u8]) -> Result<Vec<u8>, AeadError> {
    let cipher = ChaCha20Poly1305::new(AeadKey::from_slice(key));
    cipher
        .encrypt(AeadNonce::from_slice(nonce), plaintext)
        .map_err(|_| AeadError::Failed)
}

/// Decrypt `ciphertext` under `key` and `nonce`. Fails on any tamper,
/// wrong key, or wrong nonce.
///
/// # Errors
///
/// Returns `AeadError::Failed` if authentication fails.
pub fn decrypt(key: &SymKey, nonce: &Nonce, ciphertext: &[u8]) -> Result<Vec<u8>, AeadError> {
    let cipher = ChaCha20Poly1305::new(AeadKey::from_slice(key));
    cipher
        .decrypt(AeadNonce::from_slice(nonce), ciphertext)
        .map_err(|_| AeadError::Failed)
}

/// Wrap a DEK under a KEK. Convenience for envelope encryption — just
/// `encrypt` applied to a 32-byte plaintext.
///
/// # Errors
///
/// Same as `encrypt`.
pub fn wrap_dek(kek: &SymKey, nonce: &Nonce, dek: &SymKey) -> Result<Vec<u8>, AeadError> {
    encrypt(kek, nonce, dek)
}

/// Unwrap a wrapped DEK using the KEK that wrapped it. Returns `Err` on
/// tamper, wrong KEK, wrong nonce, or if the decrypted bytes are not
/// exactly 32 bytes.
///
/// # Errors
///
/// `AeadError::Failed` on auth failure; `AeadError::BadKeyLength` on
/// length mismatch.
pub fn unwrap_dek(kek: &SymKey, nonce: &Nonce, wrapped: &[u8]) -> Result<SymKey, AeadError> {
    let bytes = decrypt(kek, nonce, wrapped)?;
    if bytes.len() != 32 {
        return Err(AeadError::BadKeyLength);
    }
    let mut out = [0_u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}
