//! Property-based tests for `cosaci::attestation::{canonicalize, hash, decanonicalize}`.
//!
//! Encodes the falsifiable claims of `hypotheses/attestation-canonicalization.md`
//! (SPEC.md §10.2, class A, load-bearing — the Merkle log and trust chain
//! downstream assume `hash(attestation)` is a stable content identifier).

use cosaci::attestation::{Attestation, AttestationResult, canonicalize, decanonicalize, hash};
use hegel::generators;

// ----------------------------------------------------------------------------
// Draw helpers
// ----------------------------------------------------------------------------

fn draw_fixed_bytes<const N: usize>(tc: &hegel::TestCase) -> [u8; N] {
    let v: Vec<u8> = tc.draw(generators::binary().min_size(N).max_size(N));
    let mut arr = [0_u8; N];
    arr.copy_from_slice(&v);
    arr
}

fn draw_result(tc: &hegel::TestCase) -> AttestationResult {
    if tc.draw(generators::booleans()) {
        AttestationResult::Pass
    } else {
        AttestationResult::Fail
    }
}

fn draw_attestation(tc: &hegel::TestCase) -> Attestation {
    Attestation {
        version: tc.draw(generators::integers::<u8>()),
        job_id: draw_fixed_bytes::<16>(tc),
        commit: draw_fixed_bytes::<32>(tc),
        runner_id: tc.draw(generators::integers::<u64>()),
        result: draw_result(tc),
        environment_hash: draw_fixed_bytes::<32>(tc),
        artifact_hash: draw_fixed_bytes::<32>(tc),
        timestamp_unix_ns: tc.draw(generators::integers::<i64>()),
        signature: draw_fixed_bytes::<64>(tc),
    }
}

// ----------------------------------------------------------------------------
// Property 1 — canonicalize is deterministic.
// Same Attestation → same bytes, across repeated calls, same process.
// ----------------------------------------------------------------------------
#[hegel::test]
fn canonicalize_is_deterministic(tc: hegel::TestCase) {
    let a = draw_attestation(&tc);
    let b1 = canonicalize(&a);
    let b2 = canonicalize(&a);
    assert_eq!(
        b1, b2,
        "canonicalize produced different bytes for same input"
    );
}

// ----------------------------------------------------------------------------
// Property 2 — hash is deterministic.
// Redundant with Property 1 given hash is a pure function of bytes, but
// guards against any future accidental ambient state in `hash()`.
// ----------------------------------------------------------------------------
#[hegel::test]
fn hash_is_deterministic(tc: hegel::TestCase) {
    let a = draw_attestation(&tc);
    let h1 = hash(&a);
    let h2 = hash(&a);
    assert_eq!(h1, h2);
}

// ----------------------------------------------------------------------------
// Property 3 — round-trip equality.
// `decanonicalize(canonicalize(a)) == a`.
// ----------------------------------------------------------------------------
#[hegel::test]
fn roundtrip_equality(tc: hegel::TestCase) {
    let a = draw_attestation(&tc);
    let bytes = canonicalize(&a);
    let a2 = decanonicalize(&bytes).expect("round-trip must deserialize successfully");
    assert_eq!(
        a, a2,
        "deserialize of canonical encoding did not recover original"
    );
}

// ----------------------------------------------------------------------------
// Property 4 — idempotent re-encoding.
// `canonicalize(decanonicalize(canonicalize(a))) == canonicalize(a)`.
// This is the BYTE-LEVEL stability claim and is the single most important
// property for Merkle anchoring: a canonical encoding stays canonical.
// ----------------------------------------------------------------------------
#[hegel::test]
fn idempotent_re_encoding(tc: hegel::TestCase) {
    let a = draw_attestation(&tc);
    let b1 = canonicalize(&a);
    let a2 = decanonicalize(&b1).expect("round-trip must deserialize successfully");
    let b2 = canonicalize(&a2);
    assert_eq!(
        b1, b2,
        "re-encoding after round-trip produced different bytes"
    );
}

// ----------------------------------------------------------------------------
// Property 5 — every field contributes to the hash.
// Mutating any single field must change the hash. This guards against
// accidentally omitting a field from the serializer (a silent trust-chain
// defect: the verifier would accept forged attestations differing only
// in the un-hashed field).
// ----------------------------------------------------------------------------
#[hegel::test]
fn all_fields_contribute_to_hash(tc: hegel::TestCase) {
    let a = draw_attestation(&tc);
    let h_orig = hash(&a);

    let field_idx = tc.draw(generators::integers::<u8>().min_value(0).max_value(8));

    let mut b = a.clone();
    match field_idx {
        0 => b.version = b.version.wrapping_add(1),
        1 => {
            let i = tc.draw(generators::integers::<usize>().min_value(0).max_value(15));
            let bit = tc.draw(generators::integers::<u8>().min_value(0).max_value(7));
            b.job_id[i] ^= 1_u8 << bit;
        }
        2 => {
            let i = tc.draw(generators::integers::<usize>().min_value(0).max_value(31));
            let bit = tc.draw(generators::integers::<u8>().min_value(0).max_value(7));
            b.commit[i] ^= 1_u8 << bit;
        }
        3 => b.runner_id = b.runner_id.wrapping_add(1),
        4 => {
            b.result = match b.result {
                AttestationResult::Pass => AttestationResult::Fail,
                AttestationResult::Fail => AttestationResult::Pass,
            };
        }
        5 => {
            let i = tc.draw(generators::integers::<usize>().min_value(0).max_value(31));
            let bit = tc.draw(generators::integers::<u8>().min_value(0).max_value(7));
            b.environment_hash[i] ^= 1_u8 << bit;
        }
        6 => {
            let i = tc.draw(generators::integers::<usize>().min_value(0).max_value(31));
            let bit = tc.draw(generators::integers::<u8>().min_value(0).max_value(7));
            b.artifact_hash[i] ^= 1_u8 << bit;
        }
        7 => b.timestamp_unix_ns = b.timestamp_unix_ns.wrapping_add(1),
        8 => {
            let i = tc.draw(generators::integers::<usize>().min_value(0).max_value(63));
            let bit = tc.draw(generators::integers::<u8>().min_value(0).max_value(7));
            b.signature[i] ^= 1_u8 << bit;
        }
        _ => unreachable!("field_idx bounded by generator"),
    }

    assert_ne!(
        a, b,
        "mutation path {} produced structurally-equal value",
        field_idx
    );
    assert_ne!(
        h_orig,
        hash(&b),
        "field {} was omitted from canonical hash",
        field_idx
    );
}

// ----------------------------------------------------------------------------
// Property 6 — parse robustness.
// Arbitrary bytes must not panic the decoder; they may return Err, they may
// decode to a valid Attestation, but they must not panic.
// ----------------------------------------------------------------------------
#[hegel::test]
fn decanonicalize_never_panics(tc: hegel::TestCase) {
    let bytes: Vec<u8> = tc.draw(generators::binary().max_size(1024));
    let _ = decanonicalize(&bytes);
}
