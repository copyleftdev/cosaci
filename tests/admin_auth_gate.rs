//! Property tests for `cosaci_state::admin_auth`.
//!
//! Encodes the falsifiable properties of the admin wire-protocol
//! auth gate (issue #53 follow-on). Same shape as
//! `submission_auth_gate.rs`: signed envelope, allowlist lookup,
//! freshness window, all merged-verdict on failure.

mod common;

use common::TestClock;
use cosaci::admin_auth::{
    AdminAuthCheck, AdminKeySet, AdminRecord, fingerprint, verify_admin_hello,
};
use cosaci::signing::Keypair;
use hegel::{TestCase, generators};

const CHALLENGE: &[u8] = b"cosaci-admin-hello-v1";
const FRESHNESS_NS: u64 = 60 * 1_000_000_000;

fn draw_seed(tc: &TestCase) -> [u8; 32] {
    let v: Vec<u8> = tc.draw(generators::binary().min_size(32).max_size(32));
    let mut s = [0_u8; 32];
    s.copy_from_slice(&v);
    s
}

fn sign_hello(kp: &Keypair, ts_ns: u64) -> [u8; 64] {
    let mut signed = Vec::with_capacity(CHALLENGE.len() + 8);
    signed.extend_from_slice(CHALLENGE);
    signed.extend_from_slice(&ts_ns.to_le_bytes());
    kp.sign(&signed).to_bytes()
}

fn one_admin(tc: &TestCase) -> (AdminKeySet, Keypair, u64) {
    let admin_id: u64 = tc.draw(
        generators::integers::<u64>()
            .min_value(1)
            .max_value(1_000_000),
    );
    let seed = draw_seed(tc);
    let kp = Keypair::from_seed(seed);
    let pk = kp.verifying_key().to_bytes();
    let mut set = AdminKeySet::new();
    set.insert(AdminRecord {
        admin_id,
        signing_fp: fingerprint(&pk),
        enrolled_at_unix_ns: 0,
    })
    .expect("insert");
    (set, kp, admin_id)
}

#[hegel::test]
fn well_formed_hello_admits(tc: TestCase) {
    let (set, kp, admin_id) = one_admin(&tc);
    let clock = TestClock::new();
    clock.advance(2_000_000_000_000); // 2000s into the epoch
    let now = clock.now();
    let pk = kp.verifying_key().to_bytes();
    let sig = sign_hello(&kp, now);
    let v = verify_admin_hello(&set, &pk, now, &sig, CHALLENGE, FRESHNESS_NS, &clock);
    assert_eq!(v, AdminAuthCheck::Ok { admin_id });
}

#[hegel::test]
fn unknown_admin_rejected(tc: TestCase) {
    let (set, _, _) = one_admin(&tc);
    let clock = TestClock::new();
    clock.advance(2_000_000_000_000);
    let now = clock.now();
    // Different keypair → fingerprint not in set.
    let mut other_seed = draw_seed(&tc);
    other_seed[0] ^= 0xff;
    let attacker = Keypair::from_seed(other_seed);
    let pk = attacker.verifying_key().to_bytes();
    let sig = sign_hello(&attacker, now);
    let v = verify_admin_hello(&set, &pk, now, &sig, CHALLENGE, FRESHNESS_NS, &clock);
    assert_eq!(v, AdminAuthCheck::Unauthorized);
}

#[hegel::test]
fn tampered_ts_rejected(tc: TestCase) {
    let (set, kp, _) = one_admin(&tc);
    let clock = TestClock::new();
    clock.advance(2_000_000_000_000);
    let now = clock.now();
    let pk = kp.verifying_key().to_bytes();
    // Sign with `now`, claim `now + 1` on the wire.
    let sig = sign_hello(&kp, now);
    let v = verify_admin_hello(&set, &pk, now + 1, &sig, CHALLENGE, FRESHNESS_NS, &clock);
    assert_eq!(v, AdminAuthCheck::Unauthorized);
}

#[hegel::test]
fn stale_ts_rejected(tc: TestCase) {
    let (set, kp, _) = one_admin(&tc);
    let clock = TestClock::new();
    clock.advance(2_000_000_000_000);
    let now = clock.now();
    // Build a hello signed for a moment outside the freshness
    // window. Choose the offset deterministically from Hegel.
    let extra: u64 = tc.draw(
        generators::integers::<u64>()
            .min_value(1)
            .max_value(86_400_000_000_000),
    );
    let stale_ts = now.saturating_sub(FRESHNESS_NS).saturating_sub(extra);
    let pk = kp.verifying_key().to_bytes();
    let sig = sign_hello(&kp, stale_ts);
    let v = verify_admin_hello(&set, &pk, stale_ts, &sig, CHALLENGE, FRESHNESS_NS, &clock);
    assert_eq!(v, AdminAuthCheck::Unauthorized);
}

#[hegel::test]
fn wrong_challenge_rejected(tc: TestCase) {
    let (set, kp, _) = one_admin(&tc);
    let clock = TestClock::new();
    clock.advance(2_000_000_000_000);
    let now = clock.now();
    let pk = kp.verifying_key().to_bytes();
    let sig = sign_hello(&kp, now);
    // Pass a different challenge string to verify; the signature
    // bytes match the real challenge so verification must fail.
    let v = verify_admin_hello(
        &set,
        &pk,
        now,
        &sig,
        b"different-challenge",
        FRESHNESS_NS,
        &clock,
    );
    assert_eq!(v, AdminAuthCheck::Unauthorized);
}

#[test]
fn freshness_boundary_at_window_accepts() {
    let kp = Keypair::from_seed([0x42; 32]);
    let pk = kp.verifying_key().to_bytes();
    let mut set = AdminKeySet::new();
    set.insert(AdminRecord {
        admin_id: 1,
        signing_fp: fingerprint(&pk),
        enrolled_at_unix_ns: 0,
    })
    .expect("insert");
    let clock = TestClock::new();
    clock.advance(2_000_000_000_000);
    let now = clock.now();

    let inside = now - FRESHNESS_NS;
    let on_boundary = now - FRESHNESS_NS;
    let just_outside = now - FRESHNESS_NS - 1;

    let sig_inside = sign_hello(&kp, inside);
    assert_eq!(
        verify_admin_hello(
            &set,
            &pk,
            inside,
            &sig_inside,
            CHALLENGE,
            FRESHNESS_NS,
            &clock
        ),
        AdminAuthCheck::Ok { admin_id: 1 }
    );
    let sig_boundary = sign_hello(&kp, on_boundary);
    assert_eq!(
        verify_admin_hello(
            &set,
            &pk,
            on_boundary,
            &sig_boundary,
            CHALLENGE,
            FRESHNESS_NS,
            &clock
        ),
        AdminAuthCheck::Ok { admin_id: 1 }
    );
    let sig_outside = sign_hello(&kp, just_outside);
    assert_eq!(
        verify_admin_hello(
            &set,
            &pk,
            just_outside,
            &sig_outside,
            CHALLENGE,
            FRESHNESS_NS,
            &clock
        ),
        AdminAuthCheck::Unauthorized
    );
}
