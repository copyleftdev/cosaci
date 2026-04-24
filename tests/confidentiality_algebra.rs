//! Property-based tests for `cosaci::confidentiality`.
//!
//! Encodes the falsifiable claims of `hypotheses/confidentiality-algebra.md`
//! (class A). AEAD-layer properties: round-trip, wrong-key reject,
//! tamper reject, cross-key envelope reject. Keeps the surface narrow —
//! semantic security against an equipped attacker is a property of
//! ChaCha20-Poly1305 itself (tested upstream by the `chacha20poly1305` crate).

use cosaci::confidentiality::{decrypt, encrypt, unwrap_dek, wrap_dek, AeadError, Nonce, SymKey};
use hegel::{generators, TestCase};

// ----------------------------------------------------------------------------
// Draw helpers
// ----------------------------------------------------------------------------

fn draw_key(tc: &TestCase) -> SymKey {
    let v: Vec<u8> = tc.draw(generators::binary().min_size(32).max_size(32));
    let mut k = [0_u8; 32];
    k.copy_from_slice(&v);
    k
}

fn draw_nonce(tc: &TestCase) -> Nonce {
    let v: Vec<u8> = tc.draw(generators::binary().min_size(12).max_size(12));
    let mut n = [0_u8; 12];
    n.copy_from_slice(&v);
    n
}

fn draw_message(tc: &TestCase) -> Vec<u8> {
    tc.draw(generators::binary().max_size(1024))
}

// ----------------------------------------------------------------------------
// Property 1 — encrypt/decrypt round-trip.
// ----------------------------------------------------------------------------
#[hegel::test]
fn encrypt_decrypt_roundtrip(tc: hegel::TestCase) {
    let key = draw_key(&tc);
    let nonce = draw_nonce(&tc);
    let msg = draw_message(&tc);

    let ct = encrypt(&key, &nonce, &msg).expect("encrypt is infallible for these sizes");
    let pt = decrypt(&key, &nonce, &ct).expect("decrypt must succeed on valid ciphertext");
    assert_eq!(pt, msg, "round-trip did not recover plaintext");
}

// ----------------------------------------------------------------------------
// Property 2 — wrong-key rejection.
// ----------------------------------------------------------------------------
#[hegel::test]
fn wrong_key_decrypts_fail(tc: hegel::TestCase) {
    let k1 = draw_key(&tc);
    let k2 = draw_key(&tc);
    if k1 == k2 {
        return;
    }
    let nonce = draw_nonce(&tc);
    let msg = draw_message(&tc);
    let ct = encrypt(&k1, &nonce, &msg).expect("encrypt");
    let result = decrypt(&k2, &nonce, &ct);
    assert_eq!(
        result,
        Err(AeadError::Failed),
        "decrypt succeeded under wrong key"
    );
}

// ----------------------------------------------------------------------------
// Property 3 — wrong-nonce rejection.
// ----------------------------------------------------------------------------
#[hegel::test]
fn wrong_nonce_decrypts_fail(tc: hegel::TestCase) {
    let key = draw_key(&tc);
    let n1 = draw_nonce(&tc);
    let n2 = draw_nonce(&tc);
    if n1 == n2 {
        return;
    }
    let msg = draw_message(&tc);
    let ct = encrypt(&key, &n1, &msg).expect("encrypt");
    let result = decrypt(&key, &n2, &ct);
    assert_eq!(
        result,
        Err(AeadError::Failed),
        "decrypt succeeded under wrong nonce"
    );
}

// ----------------------------------------------------------------------------
// Property 4 — ciphertext tamper rejection.
// Flipping any single bit of the ciphertext causes authentication to fail.
// ----------------------------------------------------------------------------
#[hegel::test]
fn ciphertext_tamper_rejects(tc: hegel::TestCase) {
    let key = draw_key(&tc);
    let nonce = draw_nonce(&tc);
    // Require non-empty plaintext so the ciphertext has flippable bytes
    // beyond just the tag.
    let msg: Vec<u8> = tc.draw(generators::binary().min_size(1).max_size(1024));
    let ct = encrypt(&key, &nonce, &msg).expect("encrypt");

    let byte_idx = tc.draw(
        generators::integers::<usize>()
            .min_value(0)
            .max_value(ct.len() - 1),
    );
    let bit_idx = tc.draw(generators::integers::<u8>().min_value(0).max_value(7));
    let mut mutated = ct.clone();
    mutated[byte_idx] ^= 1_u8 << bit_idx;
    assert_ne!(mutated, ct);

    let result = decrypt(&key, &nonce, &mutated);
    assert_eq!(
        result,
        Err(AeadError::Failed),
        "decrypt accepted tampered ciphertext (byte {} bit {})",
        byte_idx,
        bit_idx
    );
}

// ----------------------------------------------------------------------------
// Property 5 — wrap_dek / unwrap_dek round-trip.
// ----------------------------------------------------------------------------
#[hegel::test]
fn wrap_unwrap_roundtrip(tc: hegel::TestCase) {
    let kek = draw_key(&tc);
    let nonce = draw_nonce(&tc);
    let dek = draw_key(&tc);
    let wrapped = wrap_dek(&kek, &nonce, &dek).expect("wrap");
    let recovered = unwrap_dek(&kek, &nonce, &wrapped).expect("unwrap");
    assert_eq!(recovered, dek, "unwrap did not recover DEK");
}

// ----------------------------------------------------------------------------
// Property 6 — cross-KEK unwrap rejection.
// A DEK wrapped under one KEK does not unwrap under another.
// ----------------------------------------------------------------------------
#[hegel::test]
fn cross_kek_unwrap_rejects(tc: hegel::TestCase) {
    let kek1 = draw_key(&tc);
    let kek2 = draw_key(&tc);
    if kek1 == kek2 {
        return;
    }
    let nonce = draw_nonce(&tc);
    let dek = draw_key(&tc);
    let wrapped = wrap_dek(&kek1, &nonce, &dek).expect("wrap");
    let result = unwrap_dek(&kek2, &nonce, &wrapped);
    assert_eq!(
        result,
        Err(AeadError::Failed),
        "unwrap succeeded under wrong KEK"
    );
}
