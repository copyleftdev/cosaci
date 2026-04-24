//! Property-based tests for `cosaci::signing`.
//!
//! Encodes the falsifiable claims of `hypotheses/tamper-rejection.md`
//! (SPEC.md §9.1, class A). Wraps `ed25519-dalek` and verifies that our
//! integration preserves Ed25519's tamper-rejection semantics.

use cosaci::signing::{Keypair, Signature, verify};
use hegel::generators;

// ----------------------------------------------------------------------------
// Draw helpers
// ----------------------------------------------------------------------------

fn draw_seed(tc: &hegel::TestCase) -> [u8; 32] {
    let v: Vec<u8> = tc.draw(generators::binary().min_size(32).max_size(32));
    let mut arr = [0_u8; 32];
    arr.copy_from_slice(&v);
    arr
}

fn draw_message(tc: &hegel::TestCase) -> Vec<u8> {
    tc.draw(generators::binary().max_size(1024))
}

fn draw_nonempty_message(tc: &hegel::TestCase) -> Vec<u8> {
    tc.draw(generators::binary().min_size(1).max_size(1024))
}

fn draw_bit_position_in(tc: &hegel::TestCase, byte_len: usize) -> (usize, u8) {
    let byte_idx = tc.draw(
        generators::integers::<usize>()
            .min_value(0)
            .max_value(byte_len - 1),
    );
    let bit_idx = tc.draw(generators::integers::<u8>().min_value(0).max_value(7));
    (byte_idx, bit_idx)
}

// ----------------------------------------------------------------------------
// Property 1 — round-trip correctness.
// Every valid (sk, pk) pair verifies its own signature over any message,
// including empty messages.
// ----------------------------------------------------------------------------
#[hegel::test]
fn sign_verify_roundtrip(tc: hegel::TestCase) {
    let seed = draw_seed(&tc);
    let msg = draw_message(&tc);

    let kp = Keypair::from_seed(seed);
    let sig = kp.sign(&msg);
    let result = verify(&kp.verifying_key(), &msg, &sig);

    assert!(
        result.is_ok(),
        "valid signature failed to verify: {:?}",
        result.err()
    );
}

// ----------------------------------------------------------------------------
// Property 2 — message mutation rejects.
// Flipping any single bit of the signed message causes verification to fail.
// ----------------------------------------------------------------------------
#[hegel::test]
fn message_mutation_rejects(tc: hegel::TestCase) {
    let seed = draw_seed(&tc);
    let msg = draw_nonempty_message(&tc);

    let kp = Keypair::from_seed(seed);
    let sig = kp.sign(&msg);

    let (byte_idx, bit_idx) = draw_bit_position_in(&tc, msg.len());
    let mut mutated = msg.clone();
    mutated[byte_idx] ^= 1_u8 << bit_idx;

    // Sanity — the mutation must actually change the message.
    assert_ne!(mutated, msg, "bit flip was a no-op");

    let result = verify(&kp.verifying_key(), &mutated, &sig);
    assert!(
        result.is_err(),
        "verifier accepted a mutated message (flipped byte {} bit {})",
        byte_idx,
        bit_idx
    );
}

// ----------------------------------------------------------------------------
// Property 3 — signature mutation rejects.
// Flipping any single bit of the signature causes verification to fail.
// Ed25519 signatures are 64 bytes; `Signature::from_bytes` is infallible
// (structural only) — strict verification is what enforces validity.
// ----------------------------------------------------------------------------
#[hegel::test]
fn signature_mutation_rejects(tc: hegel::TestCase) {
    let seed = draw_seed(&tc);
    let msg = draw_message(&tc);

    let kp = Keypair::from_seed(seed);
    let sig = kp.sign(&msg);
    let sig_bytes: [u8; 64] = sig.to_bytes();

    let (byte_idx, bit_idx) = draw_bit_position_in(&tc, 64);
    let mut mutated_bytes = sig_bytes;
    mutated_bytes[byte_idx] ^= 1_u8 << bit_idx;

    assert_ne!(mutated_bytes, sig_bytes, "bit flip was a no-op");

    let mutated_sig = Signature::from_bytes(&mutated_bytes);
    let result = verify(&kp.verifying_key(), &msg, &mutated_sig);

    assert!(
        result.is_err(),
        "verifier accepted a mutated signature (flipped byte {} bit {})",
        byte_idx,
        bit_idx
    );
}

// ----------------------------------------------------------------------------
// Property 4 — cross-key rejection.
// A signature produced by one keypair does not verify under a different
// keypair's public key.
// ----------------------------------------------------------------------------
#[hegel::test]
fn cross_key_rejects(tc: hegel::TestCase) {
    let seed_a = draw_seed(&tc);
    let seed_b = draw_seed(&tc);
    if seed_a == seed_b {
        return;
    }
    let msg = draw_message(&tc);

    let kp_a = Keypair::from_seed(seed_a);
    let kp_b = Keypair::from_seed(seed_b);
    let sig = kp_a.sign(&msg);

    let result = verify(&kp_b.verifying_key(), &msg, &sig);
    assert!(
        result.is_err(),
        "verifier accepted a signature under the wrong public key"
    );
}

// ----------------------------------------------------------------------------
// Property 5 (bonus) — determinism.
// Ed25519 is deterministic: the same (seed, msg) produces the same signature.
// ----------------------------------------------------------------------------
#[hegel::test]
fn signing_is_deterministic(tc: hegel::TestCase) {
    let seed = draw_seed(&tc);
    let msg = draw_message(&tc);

    let kp1 = Keypair::from_seed(seed);
    let kp2 = Keypair::from_seed(seed);

    let sig1 = kp1.sign(&msg);
    let sig2 = kp2.sign(&msg);

    assert_eq!(
        sig1.to_bytes(),
        sig2.to_bytes(),
        "Ed25519 signing was not deterministic for identical (seed, msg)"
    );
}
